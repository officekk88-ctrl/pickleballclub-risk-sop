import "server-only";

const WINDOW_MS = 15 * 60 * 1000;
const BLOCK_MS = 15 * 60 * 1000;
const ACCOUNT_LIMIT = 10;
const ADDRESS_LIMIT = 30;

type AttemptBucket = {
  failures: number[];
  blockedUntil: number;
};

const globalSecurityState = globalThis as typeof globalThis & {
  __pickleballLoginAttempts?: Map<string, AttemptBucket>;
};

const attempts = globalSecurityState.__pickleballLoginAttempts ?? new Map<string, AttemptBucket>();
globalSecurityState.__pickleballLoginAttempts = attempts;

function normalizeAddress(address: string): string {
  return address.trim().slice(0, 128) || "unknown";
}

function keys(email: string, address: string): Array<{ key: string; limit: number }> {
  return [
    { key: `account:${email.trim().toLowerCase()}`, limit: ACCOUNT_LIMIT },
    { key: `address:${normalizeAddress(address)}`, limit: ADDRESS_LIMIT },
  ];
}

function activeBucket(key: string, now: number): AttemptBucket {
  const existing = attempts.get(key) ?? { failures: [], blockedUntil: 0 };
  existing.failures = existing.failures.filter((timestamp) => timestamp > now - WINDOW_MS);
  if (existing.blockedUntil <= now) existing.blockedUntil = 0;
  attempts.set(key, existing);
  return existing;
}

export function loginBlockedForMs(email: string, address: string, now = Date.now()): number {
  return Math.max(0, ...keys(email, address).map(({ key }) => activeBucket(key, now).blockedUntil - now));
}

export function recordLoginFailure(email: string, address: string, now = Date.now()): void {
  for (const { key, limit } of keys(email, address)) {
    const bucket = activeBucket(key, now);
    bucket.failures.push(now);
    if (bucket.failures.length >= limit) bucket.blockedUntil = now + BLOCK_MS;
  }
}

export function clearLoginFailures(email: string): void {
  attempts.delete(`account:${email.trim().toLowerCase()}`);
}

export function resetLoginSecurityForTests(): void {
  attempts.clear();
}
