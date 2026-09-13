export interface Env {
  DB: D1Database;
  AI: any;
  HMAC_SECRET: string;
  API_KEY: string;
}

export interface IncomingPayload {
  agent_id: string;
  timestamp: string;
  nonce: string;
  ciphertext: string;
  signature: string;
}

export interface LogEvent {
  source_type: string;
  source_file: string;
  timestamp: string;
  raw_message: string;
  data: Record<string, any>;
  iocs: Array<{ type: string; value: string }>;
}
