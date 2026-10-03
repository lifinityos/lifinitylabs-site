import type { Config } from "@netlify/functions";

import {
  PROJECT_ID,
  confirmationHtml,
  doneHtml,
  getOutboundStore,
  normalizeEmail,
  parseTokenFromPath,
  receiptKey,
  securityHeaders,
  sha256,
  suppressionKey,
  tokenKey,
  type TokenRecord,
} from "../lib/outbound.mts";

function response(body: string, status: number, contentType: string) {
  return new Response(body, {
    status,
    headers: securityHeaders(contentType),
  });
}

export default async (req: Request) => {
  let token: string;
  try {
    token = parseTokenFromPath(req.url);
  } catch {
    return response("Not found\n", 404, "text/plain; charset=utf-8");
  }

  const store = getOutboundStore(req);
  const record = (await store.get(tokenKey(token), { type: "json" })) as TokenRecord | null;
  if (!record || record.schema_version !== "1.0" || record.project_id !== PROJECT_ID) {
    return response("Not found\n", 404, "text/plain; charset=utf-8");
  }
  if (Date.now() > Date.parse(record.expires_at)) {
    return response("This unsubscribe link has expired.\n", 410, "text/plain; charset=utf-8");
  }

  if (req.method === "GET") {
    return response(confirmationHtml(token), 200, "text/html; charset=utf-8");
  }

  if (req.method !== "POST") {
    return new Response("Method not allowed\n", {
      status: 405,
      headers: { ...securityHeaders("text/plain; charset=utf-8"), Allow: "GET, POST" },
    });
  }

  const body = await req.text();
  if (!body.includes("List-Unsubscribe=One-Click")) {
    return response("Invalid unsubscribe request\n", 400, "text/plain; charset=utf-8");
  }

  const consumedAt = new Date().toISOString();
  const recipient = normalizeEmail(record.recipient);
  const recipientSha = sha256(recipient);

  await store.setJSON(suppressionKey(recipient), {
    schema_version: "1.0",
    project_id: PROJECT_ID,
    recipient,
    recipient_sha256: recipientSha,
    reason: "unsubscribe",
    campaign_id: record.campaign_id,
    created_at: consumedAt,
    source: "lifinitylabs_public_unsubscribe_v1",
  });

  if (!record.consumed_at) {
    await store.setJSON(tokenKey(token), { ...record, consumed_at: consumedAt });
  }

  await store.setJSON(receiptKey(token), {
    schema_version: "1.0",
    project_id: PROJECT_ID,
    token_sha256: sha256(token),
    recipient_sha256: recipientSha,
    status: "unsubscribed",
    created_at: consumedAt,
  });

  return response(doneHtml(), 200, "text/html; charset=utf-8");
};

export const config: Config = {
  path: "/unsubscribe/*",
};
