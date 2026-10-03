import { getDeployStore, getStore } from "@netlify/blobs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

declare const Netlify: {
  env: {
    get(name: string): string | undefined;
  };
};

export const PROJECT_ID = "lifinitylabs";
export const PUBLIC_ORIGIN = "https://lifinitylabs.com";
export const STORE_NAME = "veritas-outbound-v1";
export const DEFAULT_LIFETIME_DAYS = 90;
export const MINIMUM_LIFETIME_DAYS = 60;
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,128}$/;

export type TokenRecord = {
  schema_version: "1.0";
  project_id: "lifinitylabs";
  recipient: string;
  campaign_id: string;
  issued_at: string;
  expires_at: string;
  consumed_at: string;
};

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function issueOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

export function tokenKey(token: string): string {
  if (!TOKEN_PATTERN.test(token)) {
    throw new Error("invalid unsubscribe token");
  }
  return `unsubscribe/token/${sha256(token)}`;
}

export function suppressionKey(recipient: string): string {
  return `suppression/${sha256(normalizeEmail(recipient))}`;
}

export function receiptKey(token: string): string {
  return `unsubscribe/receipt/${sha256(token)}`;
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function validRecipient(value: string): boolean {
  const normalized = normalizeEmail(value);
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized);
}

export function getInternalSecret(): string {
  return (Netlify.env.get("VERITAS_OUTBOUND_INTERNAL_TOKEN") ?? "").trim();
}

export function bearerMatches(header: string | null, expected: string): boolean {
  if (!expected) return false;
  const actual = (header ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!actual) return false;
  const left = createHash("sha256").update(actual).digest();
  const right = createHash("sha256").update(expected).digest();
  return timingSafeEqual(left, right);
}

export function getOutboundStore(req: Request) {
  const hostname = new URL(req.url).hostname.toLowerCase();
  if (hostname === "lifinitylabs.com" || hostname === "www.lifinitylabs.com") {
    return getStore(STORE_NAME, { consistency: "strong" });
  }
  return getDeployStore(STORE_NAME);
}

export function securityHeaders(contentType: string): HeadersInit {
  return {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function confirmationHtml(token: string): string {
  const action = `/unsubscribe/${encodeURIComponent(token)}`;
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Unsubscribe</title></head><body><main>" +
    "<h1>Unsubscribe</h1>" +
    "<p>Stop future commercial email from Lifinity Labs.</p>" +
    `<form method="post" action="${escapeHtml(action)}">` +
    '<input type="hidden" name="List-Unsubscribe" value="One-Click">' +
    '<button type="submit">Unsubscribe</button></form>' +
    "</main></body></html>"
  );
}

export function doneHtml(): string {
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>Unsubscribed</title></head><body><main>" +
    "<h1>Unsubscribed</h1>" +
    "<p>You will not receive further commercial email from Lifinity Labs.</p>" +
    "</main></body></html>"
  );
}

export function parseTokenFromPath(url: string): string {
  const pathname = new URL(url).pathname;
  const prefix = "/unsubscribe/";
  if (!pathname.startsWith(prefix)) throw new Error("invalid unsubscribe path");
  const encoded = pathname.slice(prefix.length);
  if (!encoded || encoded.includes("/")) throw new Error("invalid unsubscribe path");
  const token = decodeURIComponent(encoded);
  if (!TOKEN_PATTERN.test(token)) throw new Error("invalid unsubscribe token");
  return token;
}

export function addDays(now: Date, days: number): Date {
  return new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
}
