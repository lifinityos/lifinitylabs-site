import type { Config } from "@netlify/functions";

import {
  DEFAULT_LIFETIME_DAYS,
  PROJECT_ID,
  PUBLIC_ORIGIN,
  addDays,
  bearerMatches,
  getInternalSecret,
  getOutboundStore,
  issueOpaqueToken,
  normalizeEmail,
  securityHeaders,
  tokenKey,
  validRecipient,
} from "../lib/outbound.mts";

export default async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed\n", {
      status: 405,
      headers: { ...securityHeaders("text/plain; charset=utf-8"), Allow: "POST" },
    });
  }

  const expected = getInternalSecret();
  if (!expected) {
    return new Response("Unavailable\n", {
      status: 503,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }
  if (!bearerMatches(req.headers.get("authorization"), expected)) {
    return new Response("Unauthorized\n", {
      status: 401,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return new Response("Invalid JSON\n", {
      status: 400,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  if (body.project_id !== PROJECT_ID) {
    return new Response("Project not allowed\n", {
      status: 400,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }
  const recipient = normalizeEmail(String(body.recipient ?? ""));
  const campaignId = String(body.campaign_id ?? "").trim();
  if (!validRecipient(recipient) || !campaignId || campaignId.length > 128) {
    return new Response("Invalid request\n", {
      status: 400,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  const token = issueOpaqueToken();
  const issuedAt = new Date();
  const expiresAt = addDays(issuedAt, DEFAULT_LIFETIME_DAYS);
  const store = getOutboundStore(req);
  await store.setJSON(tokenKey(token), {
    schema_version: "1.0",
    project_id: PROJECT_ID,
    recipient,
    campaign_id: campaignId,
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    consumed_at: "",
  });

  return Response.json(
    {
      project_id: PROJECT_ID,
      unsubscribe_url: `${PUBLIC_ORIGIN}/unsubscribe/${encodeURIComponent(token)}`,
      expires_at: expiresAt.toISOString(),
    },
    { status: 201, headers: { "Cache-Control": "no-store" } },
  );
};

export const config: Config = {
  path: "/api/outbound/unsubscribe/issue",
};
