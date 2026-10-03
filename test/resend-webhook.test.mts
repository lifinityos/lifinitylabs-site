import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  RESEND_EVENT_TYPES,
  verifySvixSignature,
} from "../netlify/lib/outbound.mts";

const rawSecret = Buffer.from("veritas-resend-webhook-test-secret", "utf8");
const secret = "whsec_" + rawSecret.toString("base64");
const body = JSON.stringify({
  type: "email.bounced",
  data: { email_id: "em_test", to: ["test@example.org"] },
});

function signedHeaders(id = "msg_test", timestamp = 1_700_000_000) {
  const signed = `${id}.${timestamp}.${body}`;
  const signature = createHmac("sha256", rawSecret).update(signed, "utf8").digest("base64");
  return new Headers({
    "svix-id": id,
    "svix-timestamp": String(timestamp),
    "svix-signature": `v1,${signature}`,
  });
}

test("required Resend lifecycle event coverage is registered", () => {
  for (const event of [
    "email.sent",
    "email.delivered",
    "email.bounced",
    "email.complained",
    "email.failed",
    "email.suppressed",
    "suppression.added",
    "suppression.removed",
  ]) {
    assert.equal(RESEND_EVENT_TYPES.has(event), true);
  }
});

test("Svix signature verification accepts exact raw body", () => {
  const id = verifySvixSignature(
    body,
    signedHeaders(),
    secret,
    1_700_000_000,
  );
  assert.equal(id, "msg_test");
});

test("Svix signature verification rejects body changes", () => {
  assert.throws(
    () =>
      verifySvixSignature(
        body + " ",
        signedHeaders(),
        secret,
        1_700_000_000,
      ),
    /invalid svix signature/,
  );
});

test("Svix signature verification rejects stale timestamps", () => {
  assert.throws(
    () =>
      verifySvixSignature(
        body,
        signedHeaders(),
        secret,
        1_700_001_000,
      ),
    /stale svix timestamp/,
  );
});
