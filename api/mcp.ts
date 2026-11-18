import type { VercelRequest, VercelResponse } from "@vercel/node";
import { timingSafeEqual } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { QuickbaseClient } from "../src/client/quickbase";
import { CacheService } from "../src/utils/cache";
import { initializeTools, toolRegistry } from "../src/tools";
import { createMcpZodSchema } from "../src/utils/validation";

// Deliberately read-only until the owner has tested the connection.
// Update the allowlist only after reviewing tool permissions.
const ALLOWED_TOOLS = new Set([
  "test_connection", "list_tables", "get_table_fields", "get_field",
  "query_records", "get_relationships", "run_report",
]);

let initialized = false;
function init(): void {
  if (initialized) return;
  const realmHost = process.env.QUICKBASE_REALM_HOST;
  const userToken = process.env.QUICKBASE_USER_TOKEN;
  if (realmHost !== "aogalerts.quickbase.com" || !userToken) {
    throw new Error("Quickbase environment configuration is missing or incorrect");
  }
  initializeTools(new QuickbaseClient({
    realmHost,
    userToken,
    appId: process.env.QUICKBASE_APP_ID,
    cacheEnabled: false,
    cacheTtl: 3600,
    debug: false,
  }), new CacheService(3600, false));
  initialized = true;
}

function authorized(value: string | undefined): boolean {
  const secret = process.env.MCP_BEARER_TOKEN;
  if (!secret || !value?.startsWith("Bearer ")) return false;
  const received = Buffer.from(value.slice(7));
  const expected = Buffer.from(secret);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("Cache-Control", "no-store");
  if (!authorized(req.headers.authorization)) {
    res.setHeader("WWW-Authenticate", 'Bearer realm="quickbase-mcp"');
    return res.status(401).json({ error: "Unauthorized" });
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  try {
    init();
    const server = new McpServer({ name: "AOG Alerts Quickbase", version: "1.0.0" });
    for (const tool of toolRegistry.getAllTools()) {
      if (!ALLOWED_TOOLS.has(tool.name)) continue;
      server.tool(tool.name, tool.description, createMcpZodSchema(tool.paramSchema),
        async (params: Record<string, unknown>) => {
          const result = await tool.execute(params);
          if (!result.success || result.error) {
            throw new Error(result.error?.message || "Quickbase request failed");
          }
          return { content: [{ type: "text" as const, text: JSON.stringify(result.data ?? null) }] };
        });
    }
    // Stateless transport avoids in-memory sessions across Vercel invocations.
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await server.connect(transport);
    try {
      await transport.handleRequest(req, res, req.body);
    } finally {
      await server.close();
    }
  } catch (_error) {
    if (!res.headersSent) {
      return res.status(503).json({ error: "MCP service not configured or unavailable" });
    }
  }
}
