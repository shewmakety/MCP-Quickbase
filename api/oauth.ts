import type { Request, Response } from "express";
import { createHmac, timingSafeEqual, createHash } from "node:crypto";

const ISSUER = "https://aogalerts-quickbase-mcp.vercel.app";
const RESOURCE = ISSUER + "/api/mcp";
const SCOPES = ["quickbase:read", "offline_access"];
type Claims = Record<string, any>;

function signingKey(purpose: string): Buffer {
  const secret = process.env.MCP_BEARER_TOKEN;
  if (!secret || Buffer.byteLength(secret) < 24) throw new Error("MCP_BEARER_TOKEN not configured");
  return createHmac("sha256", secret).update("aogalerts-mcp-oauth:" + purpose).digest();
}
function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function token(data: Claims, purpose: string, seconds: number): string {
  const payload = Buffer.from(JSON.stringify({ ...data, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+seconds })).toString("base64url");
  const sig = createHmac("sha256", signingKey(purpose)).update(payload).digest("base64url");
  return payload + "." + sig;
}
function decode(value: unknown, purpose: string): Claims | null {
  if (typeof value !== "string" || value.length > 16000) return null;
  const chunks = value.split(".");
  if (chunks.length !== 2) return null;
  const sig = createHmac("sha256", signingKey(purpose)).update(chunks[0]).digest("base64url");
  if (!safeEqual(chunks[1], sig)) return null;
  try {
    const data = JSON.parse(Buffer.from(chunks[0], "base64url").toString());
    const now = Math.floor(Date.now()/1000);
    if (!data || typeof data !== "object" || typeof data.exp !== "number" || data.exp <= now || data.iat > now + 60) return null;
    return data;
  } catch { return null; }
}
function sendJson(res: Response, status: number, body: unknown): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.status(status).json(body);
}
function form(req: Request): Record<string,string> {
  const body = req.body;
  if (typeof body === "string" || Buffer.isBuffer(body)) return Object.fromEntries(new URLSearchParams(body.toString()));
  if (body && typeof body === "object") return Object.fromEntries(Object.entries(body).map(([k,v]) => [k,String(v??"")]));
  return {};
}
function allowedRedirect(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" &&
      (u.hostname === "chatgpt.com" || u.hostname === "chat.openai.com" ||
       u.hostname === "openai.com" || u.hostname.endsWith(".openai.com")) &&
      !u.username && !u.password && !u.hash;
  } catch { return false; }
}
function validResource(resource: string): boolean {
  return resource === RESOURCE || resource === ISSUER;
}
function getClient(id: string): Claims | null {
  if (!id.startsWith("qb_")) return null;
  return decode(id.slice(3), "client");
}
function esc(x: string): string {
  return x.replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c] || c));
}
export function oauthClaims(authHeader: string | undefined): Claims | null {
  if (!authHeader?.startsWith("Bearer ")) return null;
  const bearer = authHeader.slice(7);
  // Backwards-compatible owner-token authentication (no OAuth metadata leaks).
  if (process.env.MCP_BEARER_TOKEN && safeEqual(bearer, process.env.MCP_BEARER_TOKEN)) return { scope: "quickbase:read", aud: RESOURCE };
  const claims = decode(bearer, "access");
  if (!claims || claims.iss !== ISSUER || claims.aud !== RESOURCE || !String(claims.scope||"").split(" ").includes("quickbase:read")) return null;
  return claims;
}
export function resourceChallenge(): string {
  return 'Bearer realm="AOG Quickbase", resource_metadata="' + ISSUER + '/.well-known/oauth-protected-resource", scope="quickbase:read"';
}

export default async function handler(req: Request, res: Response) {
  try {
    res.setHeader("Cache-Control", "no-store");
    const path = (req.url || "").split("?")[0].replace(/\/$/, "");
    // Vercel rewrites retain original URL in most runtimes; explicit route discriminator
    // supplied as a query fallback handles rewritten requests consistently.
    const action = String((req.query as any)?.oauth_action || (
      path.endsWith("oauth-protected-resource") || path.endsWith("oauth-protected-resource/api/mcp") ? "resource" :
      path.endsWith("oauth-authorization-server") || path.endsWith("openid-configuration") ? "metadata" :
      path.endsWith("/register") ? "register" : path.endsWith("/authorize") ? "authorize" :
      path.endsWith("/token") ? "token" : ""
    ));
    if (action === "resource" && req.method === "GET") {
      return sendJson(res, 200, { resource: RESOURCE, authorization_servers: [ISSUER], scopes_supported: SCOPES, bearer_methods_supported: ["header"] });
    }
    if (action === "metadata" && req.method === "GET") {
      return sendJson(res, 200, {
        issuer: ISSUER, authorization_endpoint: ISSUER+"/authorize", token_endpoint: ISSUER+"/token",
        registration_endpoint: ISSUER+"/register", response_types_supported:["code"],
        grant_types_supported:["authorization_code","refresh_token"],
        token_endpoint_auth_methods_supported:["none"], code_challenge_methods_supported:["S256"],
        scopes_supported:SCOPES, client_id_metadata_document_supported:false,
      });
    }
    if (action === "register" && req.method === "POST") {
      const b = req.body || {};
      const redirects = b.redirect_uris;
      if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 5 ||
        !redirects.every((x: unknown)=>typeof x==="string" && allowedRedirect(x))) {
        return sendJson(res, 400, { error:"invalid_redirect_uri" });
      }
      if (b.token_endpoint_auth_method && b.token_endpoint_auth_method !== "none") {
        return sendJson(res, 400, { error:"invalid_client_metadata" });
      }
      const client_id = "qb_" + token({redirects}, "client", 365*24*3600);
      return sendJson(res, 201, {
        client_id, redirect_uris: redirects, client_name: String(b.client_name||"ChatGPT"),
        token_endpoint_auth_method:"none", grant_types:["authorization_code","refresh_token"],
        response_types:["code"], scope:SCOPES.join(" "),
      });
    }
    if (action === "authorize" && req.method === "GET") {
      const q = req.query as Record<string,string>;
      const client = getClient(q.client_id||"");
      if (!client || !Array.isArray(client.redirects) || !client.redirects.includes(q.redirect_uri) ||
          !allowedRedirect(q.redirect_uri) || q.response_type !== "code" ||
          q.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge||"") ||
          (q.resource && !validResource(q.resource))) {
        return sendJson(res,400,{error:"invalid_request",error_description:"Invalid OAuth client, redirect, PKCE or resource"});
      }
      const params = {client_id:q.client_id,redirect_uri:q.redirect_uri,challenge:q.code_challenge,
        state:q.state||"",scope:"quickbase:read offline_access",resource:q.resource||RESOURCE};
      const requestToken=token(params,"request",600);
      res.setHeader("Content-Type","text/html; charset=utf-8");
      res.setHeader("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://chatgpt.com https://chat.openai.com https://openai.com https://*.openai.com; base-uri 'none'; frame-ancestors 'none'");
      res.setHeader("X-Frame-Options","DENY");
      return res.status(200).send('<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Quickbase access</title></head><body style="font-family:system-ui;max-width:440px;margin:10vh auto;padding:20px"><h2>Connect ChatGPT to AOG Alerts Quickbase</h2><p>Allow read-only access to your Quickbase records. No changes or deletions will be available.</p><form method="POST" action="/authorize?oauth_action=authorize"><input type="hidden" name="request" value="'+esc(requestToken)+'"><label>Enter your private MCP bearer token<br><input type="password" name="password" required autocomplete="off" style="width:100%;padding:12px;margin:8px 0"></label><button type="submit" style="padding:12px 24px">Authorize</button></form></body></html>');
    }
    if (action === "authorize" && req.method === "POST") {
      const b=form(req), data=decode(b.request,"request"), secret=process.env.MCP_BEARER_TOKEN;
      console.info("OAuth authorization POST", { bodyParsed: Boolean(b.request), requestValid: Boolean(data), tokenEntered: Boolean(b.password) });
      if (!data || !secret || !safeEqual(b.password||"",secret) ||
          !getClient(data.client_id) || !allowedRedirect(data.redirect_uri)) {
        return res.status(403).set("Content-Type","text/html; charset=utf-8").send('<!doctype html><html><body style="font-family:system-ui;max-width:520px;margin:10vh auto"><h2>Authorization failed</h2><p>The credential was not accepted or the authorization request expired. Return to ChatGPT and choose Connect again to get a fresh authorization page.</p></body></html>');
      }
      const code=token({...data,iss:ISSUER}, "code", 120);
      const redirect=new URL(data.redirect_uri);
      redirect.searchParams.set("code",code);
      if(data.state) redirect.searchParams.set("state",data.state);
      console.info("OAuth authorization accepted; redirecting to callback");
      return res.redirect(303,redirect.toString());
    }
    if (action === "token" && req.method === "POST") {
      const b=form(req);
      const client=getClient(b.client_id||"");
      if (!client) return sendJson(res,401,{error:"invalid_client"});
      if (b.grant_type === "authorization_code") {
        const code=decode(b.code,"code");
        if(!code || code.client_id!==b.client_id || code.iss!==ISSUER ||
           !client.redirects.includes(b.redirect_uri) || code.redirect_uri!==b.redirect_uri ||
           !/^[A-Za-z0-9._~-]{43,128}$/.test(b.code_verifier||"") ||
           createHash("sha256").update(b.code_verifier).digest("base64url") !== code.challenge ||
           (b.resource && b.resource!==code.resource)) return sendJson(res,400,{error:"invalid_grant"});
        const access_token=token({iss:ISSUER,aud:RESOURCE,client_id:b.client_id,scope:"quickbase:read"}, "access",3600);
        const refresh_token=token({iss:ISSUER,aud:RESOURCE,client_id:b.client_id,scope:"quickbase:read"}, "refresh",30*24*3600);
        return sendJson(res,200,{access_token,refresh_token,token_type:"Bearer",expires_in:3600,scope:"quickbase:read offline_access"});
      }
      if (b.grant_type === "refresh_token") {
        const refresh=decode(b.refresh_token,"refresh");
        if(!refresh || refresh.iss!==ISSUER || refresh.aud!==RESOURCE || refresh.client_id!==b.client_id ||
           (b.resource && !validResource(b.resource))) return sendJson(res,400,{error:"invalid_grant"});
        return sendJson(res,200,{
          access_token:token({iss:ISSUER,aud:RESOURCE,client_id:b.client_id,scope:"quickbase:read"},"access",3600),
          refresh_token:token({iss:ISSUER,aud:RESOURCE,client_id:b.client_id,scope:"quickbase:read"},"refresh",30*24*3600),
          token_type:"Bearer",expires_in:3600,scope:"quickbase:read offline_access",
        });
      }
      return sendJson(res,400,{error:"unsupported_grant_type"});
    }
    return sendJson(res,404,{error:"not_found"});
  } catch {
    return sendJson(res,503,{error:"server_unavailable"});
  }
}
