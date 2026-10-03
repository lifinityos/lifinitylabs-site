import type { Config } from "@netlify/functions";

import {
  PROJECT_ID,
  RESEND_EVENT_TYPES,
  getOutboundStore,
  getResendWebhookSecret,
  normalizeEmail,
  resendEventKey,
  securityHeaders,
  sha256,
  suppressionKey,
  verifySvixSignature,
} from "../lib/outbound.mts";

type EventData = Record<string, unknown>;

function json(body: Record<string, unknown>, status = 200) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function recipientFromData(data: EventData): string {
  const to = data.to;
  if (Array.isArray(to)) {
    for (const value of to) {
      const email = normalizeEmail(String(value ?? ""));
      if (email) return email;
    }
  }
  for (const key of ["email", "email_address", "recipient", "address"]) {
    const email = normalizeEmail(String(data[key] ?? ""));
    if (email) return email;
  }
  const suppression = data.suppression;
  if (suppression && typeof suppression === "object") {
    for (const key of ["email", "email_address", "recipient", "address"]) {
      const email = normalizeEmail(String((suppression as EventData)[key] ?? ""));
      if (email) return email;
    }
  }
  return "";
}

function providerMessageId(data: EventData): string {
  return String(data.email_id ?? data.id ?? "").trim();
}

function suppressionReason(type: string): string {
  if (type === "email.bounced") return "hard_bounce";
  if (type === "email.complained") return "complaint";
  if (type === "email.suppressed" || type === "suppression.added") return "provider_suppression";
  return "";
}

export default async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed\n", {
      status: 405,
      headers: { ...securityHeaders("text/plain; charset=utf-8"), Allow: "POST" },
    });
  }

  const signingSecret = getResendWebhookSecret();
  if (!signingSecret) {
    return new Response("Unavailable\n", {
      status: 503,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  const rawBody = await req.text();
  let eventId: string;
  try {
    eventId = verifySvixSignature(rawBody, req.headers, signingSecret);
  } catch {
    return new Response("Unauthorized\n", {
      status: 401,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawBody) as Record<string, unknown>;
  } catch {
    return new Response("Invalid JSON\n", {
      status: 400,
      headers: securityHeaders("text/plain; charset=utf-8"),
    });
  }

  const type = String(payload.type ?? "").trim();
  if (!RESEND_EVENT_TYPES.has(type)) {
    return json({ ok: true, ignored: true });
  }

  const data =
    payload.data && typeof payload.data === "object"
      ? (payload.data as EventData)
      : {};
  const recipient = recipientFromData(data);
  const recipientSha = recipient ? sha256(recipient) : "";
  const store = getOutboundStore(req);
  const eventKey = resendEventKey(eventId);

  const existing = await store.get(eventKey, { type: "json" });
  if (existing) {
    return json({ ok: true, duplicate: true });
  }

  const eventReceipt = {
    schema_version: "1.0",
    project_id: PROJECT_ID,
    event_id_sha256: sha256(eventId),
    event_type: type,
    created_at: String(payload.created_at ?? data.created_at ?? ""),
    provider_message_id: providerMessageId(data),
    recipient_sha256: recipientSha,
  };

  const reason = suppressionReason(type);
  if (reason && recipient) {
    await store.setJSON(suppressionKey(recipient), {
      schema_version: "1.0",
      project_id: PROJECT_ID,
      recipient,
      recipient_sha256: recipientSha,
      reason,
      created_at: eventReceipt.created_at,
      provider_message_id: eventReceipt.provider_message_id,
      source: "resend_webhook_v1",
    });
  } else if (type === "suppression.removed" && recipient) {
    await store.delete(suppressionKey(recipient));
  }

  await store.setJSON(eventKey, eventReceipt);
  return json({ ok: true });
};

export const config: Config = {
  path: "/api/outbound/resend/webhook",
};
