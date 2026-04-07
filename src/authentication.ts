/**
 * Shared authentication contract between MCP clients and the firewall.
 *
 * Clients prove identity ownership by signing an AgentGate action execution
 * request for a lightweight authentication action tied to their claimed bond.
 */

export const AUTHENTICATION_ACTION_TYPE = "mcp.firewall.authenticate";
export const AUTHENTICATION_EXPOSURE_CENTS = 1;

const AUTHENTICATION_PURPOSE = "mcp-firewall-authenticate";

export interface AuthenticationActionBody {
  identityId: string;
  bondId: string;
  actionType: typeof AUTHENTICATION_ACTION_TYPE;
  payload: {
    purpose: typeof AUTHENTICATION_PURPOSE;
    sessionId: string;
  };
  exposure_cents: typeof AUTHENTICATION_EXPOSURE_CENTS;
}

export interface AuthenticateToolArguments {
  identityId: string;
  bondId: string;
  nonce: string;
  timestamp: string;
  signature: string;
}

export function buildAuthenticationAction(
  identityId: string,
  bondId: string,
  sessionId: string,
): AuthenticationActionBody {
  return {
    identityId,
    bondId,
    actionType: AUTHENTICATION_ACTION_TYPE,
    payload: {
      purpose: AUTHENTICATION_PURPOSE,
      sessionId,
    },
    exposure_cents: AUTHENTICATION_EXPOSURE_CENTS,
  };
}
