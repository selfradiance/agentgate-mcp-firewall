/**
 * AgentGate Client
 *
 * The firewall's client for communicating with AgentGate.
 * Manages Ed25519 identity, signs all requests, and exposes
 * the AgentGate operations the firewall needs.
 */

import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import {
  createHash,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";

const DEFAULT_AGENTGATE_URL = "http://127.0.0.1:3000";
const DEFAULT_IDENTITY_PATH = "./agent-identity-firewall.json";

/**
 * Validate that a value is safe to interpolate into a URL path segment.
 * Rejects path separators, traversal sequences, and non-string types.
 */
function validatePathSegment(value: unknown, label: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (value.includes("/") || value.includes("\\") || value.includes("..")) {
    throw new Error(`${label} contains invalid characters`);
  }
}

export interface AgentGateClientOptions {
  /** AgentGate base URL (default: http://127.0.0.1:3000) */
  agentgateUrl?: string;
  /** Path to the Ed25519 identity file (default: ./agent-identity-firewall.json) */
  identityPath?: string;
  /** Optional API key for non-dev-mode AgentGate instances */
  apiKey?: string;
}

export interface IdentityKeyPair {
  publicKey: string;
  privateKey: string;
  identityId?: string;
}

export interface IdentitySummary {
  identityId: string;
  publicKey: string;
  reputation: {
    score: number;
    stats: {
      locks: number;
      actions: number;
      successes: number;
      failures: number;
      malicious: number;
    };
  };
}

export interface BondResult {
  bondId: string;
  status: string;
}

export interface ActionResult {
  actionId: string;
  status: string;
}

export interface ResolveResult {
  actionId: string;
  outcome: string;
  refundCents: number;
  burnedCents: number;
  slashedCents: number;
}

export class AgentGateClient {
  private baseUrl: string;
  private identityPath: string;
  private apiKey: string | undefined;
  private keyPair: IdentityKeyPair | null = null;

  constructor(options: AgentGateClientOptions = {}) {
    this.baseUrl =
      options.agentgateUrl ??
      process.env.AGENTGATE_URL ??
      DEFAULT_AGENTGATE_URL;
    this.identityPath =
      options.identityPath ??
      process.env.FIREWALL_IDENTITY_PATH ??
      DEFAULT_IDENTITY_PATH;
    this.apiKey = options.apiKey ?? process.env.AGENTGATE_REST_KEY;
  }

  /** Get the identity ID (only available after registerIdentity). */
  get identityId(): string | undefined {
    return this.keyPair?.identityId;
  }

  /** Get the public key. */
  get publicKey(): string | undefined {
    return this.keyPair?.publicKey;
  }

  /**
   * Load or generate Ed25519 keypair, then register with AgentGate.
   * If the identity file exists and has an identityId, skips registration.
   */
  async registerIdentity(): Promise<{ identityId: string }> {
    this.keyPair = this.loadOrGenerateKeyPair();

    // If already registered, just return the existing ID
    if (this.keyPair.identityId) {
      return { identityId: this.keyPair.identityId };
    }

    // Register the public key on AgentGate
    const body = {
      publicKey: this.keyPair.publicKey,
      agentName: "mcp-firewall",
    };

    const response = await this.signedFetch("POST", "/v1/identities", body);

    if (response.status === 409) {
      // Already registered — identity file may have been missing the ID.
      // Try to look it up by making a health check or just re-save.
      throw new Error(
        "This public key is already registered on AgentGate but the local identity file is missing the identityId. Delete the identity file and restart.",
      );
    }

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Failed to register identity on AgentGate: ${response.status} ${text}`,
      );
    }

    const result = (await response.json()) as { identityId: string };

    // Save the identity ID back to the file
    this.keyPair.identityId = result.identityId;
    this.saveKeyPair(this.keyPair);

    return result;
  }

  /**
   * Check if an identity exists on AgentGate and return its summary.
   * The reputation stats can be used to assess whether the identity is trustworthy.
   */
  async checkIdentity(identityId: string): Promise<IdentitySummary> {
    validatePathSegment(identityId, "identityId");
    const response = await fetch(`${this.baseUrl}/v1/identities/${identityId}`);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Failed to check identity on AgentGate: ${response.status} ${text}`,
      );
    }

    return (await response.json()) as IdentitySummary;
  }

  /**
   * Lock a bond on AgentGate for a given identity.
   */
  async lockBond(
    identityId: string,
    amountCents: number,
    currency: string,
    ttlSeconds: number,
    reason: string,
  ): Promise<BondResult> {
    const body = {
      identityId,
      amountCents,
      currency,
      ttlSeconds,
      reason,
    };

    const response = await this.signedFetch("POST", "/v1/bonds/lock", body);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Failed to lock bond on AgentGate: ${response.status} ${text}`,
      );
    }

    return (await response.json()) as BondResult;
  }

  /**
   * Execute a bonded action on AgentGate.
   */
  async executeBondedAction(
    bondId: string,
    actionType: string,
    payload: unknown,
    exposureCents: number,
  ): Promise<ActionResult> {
    if (!this.keyPair?.identityId) {
      throw new Error("Identity not registered. Call registerIdentity() first.");
    }

    const body = {
      identityId: this.keyPair.identityId,
      bondId,
      actionType,
      payload,
      exposure_cents: exposureCents,
    };

    const response = await this.signedFetch(
      "POST",
      "/v1/actions/execute",
      body,
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Failed to execute action on AgentGate: ${response.status} ${text}`,
      );
    }

    return (await response.json()) as ActionResult;
  }

  /**
   * Resolve an action on AgentGate.
   */
  async resolveAction(
    actionId: string,
    outcome: "success" | "failed" | "malicious",
  ): Promise<ResolveResult> {
    validatePathSegment(actionId, "actionId");
    if (!this.keyPair?.identityId) {
      throw new Error("Identity not registered. Call registerIdentity() first.");
    }

    const body = {
      outcome,
      resolverId: this.keyPair.identityId,
    };

    const response = await this.signedFetch(
      "POST",
      `/v1/actions/${actionId}/resolve`,
      body,
    );

    if (!response.ok) {
      const text = await response.text();
      throw new Error(
        `Failed to resolve action on AgentGate: ${response.status} ${text}`,
      );
    }

    return (await response.json()) as ResolveResult;
  }

  /**
   * Make a signed HTTP request to AgentGate.
   */
  private async signedFetch(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Response> {
    if (!this.keyPair) {
      throw new Error("No keypair loaded. Call registerIdentity() first.");
    }

    const nonce = randomUUID();
    const timestamp = String(Date.now());
    const signature = this.signRequest(
      nonce,
      method,
      path,
      timestamp,
      body,
    );

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "x-nonce": nonce,
      "x-agentgate-timestamp": timestamp,
      "x-agentgate-signature": signature,
    };

    if (this.apiKey) {
      headers["x-agentgate-key"] = this.apiKey;
    }

    return fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: JSON.stringify(body),
    });
  }

  /**
   * Sign a request using AgentGate's format:
   * sha256(nonce + method + path + timestamp + JSON.stringify(body))
   */
  private signRequest(
    nonce: string,
    method: string,
    path: string,
    timestamp: string,
    body: unknown,
  ): string {
    const message = createHash("sha256")
      .update(
        `${nonce}${method}${path}${timestamp}${JSON.stringify(body)}`,
      )
      .digest();

    const privateKeyBytes = Buffer.from(this.keyPair!.privateKey, "base64");
    const publicKeyBytes = Buffer.from(this.keyPair!.publicKey, "base64");

    // Convert to base64url for JWK format
    const toBase64Url = (buf: Buffer) =>
      buf
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");

    const privateKey = createPrivateKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: toBase64Url(publicKeyBytes),
        d: toBase64Url(privateKeyBytes),
      },
      format: "jwk",
    });

    const signature = sign(null, message, privateKey);
    return signature.toString("base64");
  }

  /**
   * Load keypair from file or generate a new one.
   */
  private loadOrGenerateKeyPair(): IdentityKeyPair {
    if (existsSync(this.identityPath)) {
      const raw = readFileSync(this.identityPath, "utf-8");
      const parsed = JSON.parse(raw) as IdentityKeyPair;

      if (!parsed.publicKey || !parsed.privateKey) {
        throw new Error(
          `Identity file ${this.identityPath} is missing publicKey or privateKey`,
        );
      }

      return parsed;
    }

    // Generate a new Ed25519 keypair
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");

    const publicKeyBase64 = Buffer.from(
      publicKey.export({ type: "spki", format: "der" }).subarray(-32),
    ).toString("base64");

    const privateKeyBase64 = Buffer.from(
      privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
    ).toString("base64");

    const keyPair: IdentityKeyPair = {
      publicKey: publicKeyBase64,
      privateKey: privateKeyBase64,
    };

    this.saveKeyPair(keyPair);
    return keyPair;
  }

  /**
   * Save keypair to the identity file.
   */
  private saveKeyPair(keyPair: IdentityKeyPair): void {
    writeFileSync(this.identityPath, JSON.stringify(keyPair, null, 2) + "\n");
  }
}
