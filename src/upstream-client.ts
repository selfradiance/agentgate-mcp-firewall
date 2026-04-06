/**
 * Upstream MCP Client
 *
 * Connects to an upstream MCP server over Streamable HTTP,
 * discovers its available tools, and exposes them for the
 * firewall proxy to forward calls through.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export interface UpstreamClientOptions {
  /** Full URL of the upstream MCP server endpoint (e.g. "http://127.0.0.1:4444/mcp") */
  url: string;
  /** Client name reported during MCP handshake */
  clientName?: string;
  /** Client version reported during MCP handshake */
  clientVersion?: string;
}

export interface CallToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export class UpstreamClient {
  private client: Client;
  private transport: StreamableHTTPClientTransport;
  private connected = false;

  constructor(private options: UpstreamClientOptions) {
    this.client = new Client({
      name: options.clientName ?? "mcp-firewall",
      version: options.clientVersion ?? "0.1.0",
    });

    this.transport = new StreamableHTTPClientTransport(
      new URL(options.url),
    );
  }

  /** Connect to the upstream MCP server. */
  async connect(): Promise<void> {
    if (this.connected) return;
    await this.client.connect(this.transport);
    this.connected = true;
  }

  /** List all tools exposed by the upstream server. */
  async listTools(): Promise<Tool[]> {
    if (!this.connected) {
      throw new Error("UpstreamClient is not connected. Call connect() first.");
    }
    const result = await this.client.listTools();
    return result.tools;
  }

  /** Call a tool on the upstream server. */
  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    if (!this.connected) {
      throw new Error("UpstreamClient is not connected. Call connect() first.");
    }
    const result = await this.client.callTool({ name, arguments: args });
    return result as CallToolResult;
  }

  /** Disconnect from the upstream server. */
  async close(): Promise<void> {
    if (!this.connected) return;
    await this.client.close();
    this.connected = false;
  }
}
