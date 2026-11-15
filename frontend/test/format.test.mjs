// Unit tests for the pure presentation helpers. Run with: npm test (uses node:test).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatBytes, errorMessage, guessIndicatorType, isHttpUrl, isPending, riskKey,
} from "../src/utils/format.js";

test("formatBytes uses binary units and dashes for missing values", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 MB");
  assert.equal(formatBytes(null), "-");
});

test("guessIndicatorType mirrors the backend detector", () => {
  assert.equal(guessIndicatorType("8.8.8.8"), "ip");
  assert.equal(guessIndicatorType("2001:db8::1"), "ip");
  assert.equal(guessIndicatorType("example.com"), "domain");
  assert.equal(guessIndicatorType("https://example.com/x"), "url");
  assert.equal(guessIndicatorType("a".repeat(32)), "md5");
  assert.equal(guessIndicatorType("a".repeat(40)), "sha1");
  assert.equal(guessIndicatorType("a".repeat(64)), "sha256");
  assert.equal(guessIndicatorType("not an indicator!!"), null);
  assert.equal(guessIndicatorType(""), null);
});

test("isHttpUrl accepts only http and https with a host", () => {
  assert.equal(isHttpUrl("https://example.com/a"), true);
  assert.equal(isHttpUrl("ftp://example.com"), false);
  assert.equal(isHttpUrl("javascript:alert(1)"), false);
  assert.equal(isHttpUrl("not a url"), false);
});

test("errorMessage prefers the API detail and never returns a stack trace", () => {
  assert.equal(errorMessage({ response: { data: { detail: "Unsupported file type." } } }), "Unsupported file type.");
  assert.match(errorMessage({ response: { status: 429 } }), /Too many requests/);
  assert.equal(errorMessage({ message: "boom at line 4" }, "Fallback."), "Fallback.");
});

test("pending statuses and risk keys", () => {
  assert.equal(isPending("queued"), true);
  assert.equal(isPending("complete"), false);
  assert.equal(riskKey(null), "unknown");
  assert.equal(riskKey("critical"), "critical");
});
