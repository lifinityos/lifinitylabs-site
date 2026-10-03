import assert from "node:assert/strict";
import test from "node:test";

import {
  PUBLIC_ORIGIN,
  TOKEN_PATTERN,
  bearerMatches,
  confirmationHtml,
  parseTokenFromPath,
  sha256,
} from "../netlify/lib/outbound.mts";

test("opaque token URL parsing is bounded", () => {
  const token = "A".repeat(43);
  assert.equal(TOKEN_PATTERN.test(token), true);
  assert.equal(
    parseTokenFromPath(`${PUBLIC_ORIGIN}/unsubscribe/${token}`),
    token,
  );
  assert.throws(() => parseTokenFromPath(`${PUBLIC_ORIGIN}/unsubscribe/x`));
});

test("confirmation page contains no recipient data", () => {
  const token = "B".repeat(43);
  const body = confirmationHtml(token);
  assert.match(body, /Unsubscribe/);
  assert.match(body, new RegExp(token));
  assert.doesNotMatch(body, /@/);
});

test("bearer comparison fails closed", () => {
  assert.equal(bearerMatches("Bearer secret", "secret"), true);
  assert.equal(bearerMatches("Bearer wrong", "secret"), false);
  assert.equal(bearerMatches(null, "secret"), false);
  assert.equal(bearerMatches("Bearer secret", ""), false);
});

test("sha256 is deterministic", () => {
  assert.equal(sha256("recipient@example.org"), sha256("recipient@example.org"));
  assert.notEqual(sha256("recipient@example.org"), sha256("other@example.org"));
});
