# AOG Alerts Quickbase MCP — remote setup

This fork adds a **read-only**, authenticated, stateless MCP endpoint at `/api/mcp`.

## Required Vercel environment variables

Set the following in **Vercel → Project → Settings → Environment Variables**:

| Name | Value | Type |
| --- | --- | --- |
| `QUICKBASE_REALM_HOST` | `aogalerts.quickbase.com` | Plain |
| `QUICKBASE_USER_TOKEN` | Your Quickbase user token | Sensitive |
| `MCP_BEARER_TOKEN` | A separate, securely generated random token of 32+ bytes | Sensitive |
| `QUICKBASE_APP_ID` | Optional default app ID | Plain |

Never commit the tokens to GitHub. Rotate immediately if either token is exposed.

## Security

All routes in this deployment are accessible only through the bearer-checked
`/api/mcp` handler. No legacy unauthenticated Express API is deployed.
The exposed tools are limited to: `test_connection`, `list_tables`,
`get_table_fields`, `get_field`, `query_records`,
`get_relationships`, `run_report`. No writes are exposed.

The existing Quickbase user token still governs the underlying Quickbase
permissions; prefer a dedicated least-privilege read-only service account.

## Connect an MCP client

Endpoint: `https://YOUR-VERCEL-DEPLOYMENT.vercel.app/api/mcp`

Authentication: `Authorization: Bearer <MCP_BEARER_TOKEN>`.

This is a static bearer-token implementation, **not OAuth**. Some ChatGPT
custom app connection flows require OAuth and might not support supplying
a fixed Authorization header; in that case an OAuth authorization server
and protected-resource metadata need to be added before ChatGPT can connect.

## Deploy

Create a Vercel project connected to this GitHub fork. Set the environment
variables **before** testing the endpoint. A request with no bearer token
must return HTTP 401; POST with the correct bearer token and MCP initialize
payload should respond with MCP JSON-RPC. Test read-only tools before
considering any write tools.
