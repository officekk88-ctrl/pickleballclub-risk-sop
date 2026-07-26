import assert from "node:assert/strict";
import test from "node:test";
import {
  clearLoginFailures,
  loginBlockedForMs,
  recordLoginFailure,
  resetLoginSecurityForTests,
} from "../src/lib/login-security";

test("login failures block repeated account attempts and expire", () => {
  resetLoginSecurityForTests();
  const now = 1_000_000;
  for (let attempt = 0; attempt < 9; attempt += 1) {
    recordLoginFailure("USER@example.com", "203.0.113.10", now + attempt);
  }
  assert.equal(loginBlockedForMs("user@example.com", "203.0.113.10", now + 10), 0);
  recordLoginFailure("user@example.com", "203.0.113.10", now + 10);
  assert.ok(loginBlockedForMs("user@example.com", "203.0.113.11", now + 11) > 0);
  assert.equal(loginBlockedForMs("user@example.com", "203.0.113.11", now + 15 * 60 * 1000 + 11), 0);
});

test("successful login clears the account bucket", () => {
  resetLoginSecurityForTests();
  const now = 2_000_000;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    recordLoginFailure("user@example.com", `203.0.113.${attempt}`, now + attempt);
  }
  assert.ok(loginBlockedForMs("user@example.com", "198.51.100.1", now + 11) > 0);
  clearLoginFailures("USER@example.com");
  assert.equal(loginBlockedForMs("user@example.com", "198.51.100.1", now + 12), 0);
});
