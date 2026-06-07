<h1 align=center>Node-SafeURL</h1>

<p align=center>SSRF-safe URL validation library for Node.js</p>

Lightweight TypeScript library for validating URLs to prevent Server-Side Request Forgery (SSRF) attacks. It blocks requests to private IP ranges, localhost, link-local addresses, and other special-purpose networks using Microsoft's maintained [`@microsoft/antissrf`](https://www.npmjs.com/package/@microsoft/antissrf) block lists.

## About

`node-safeurl` provides the following exports:

- **`fetch(input, init?)`** — SSRF-safe drop-in replacement for the global `fetch`. Validates the URL (and every redirect hop) before making the request, and returns a `TypedResponse`. Pass `{ safeUrl: false }` to opt out of validation entirely, or `{ safeUrlAllow: [...] }` to allow specific private-network origins while keeping all other SSRF checks active.
- **`TypedResponse`** — Subclass of `Response` that adds a `.typed(schema)` method for runtime-validated JSON parsing via TypeBox.
- **`FetchInit`** — TypeScript interface extending `RequestInit` with the optional `safeUrl` boolean and `safeUrlAllow` string-array fields.
- **`isSafeUrl(href, opts?)`** — Async function that validates a URL is safe to fetch. Checks protocol, hostname, IP literals, and performs DNS resolution to guard against DNS rebinding attacks. Pass `{ allow: [...] }` to exempt specific origins or hostnames from all checks.
- **`SafeUrlOptions`** — TypeScript interface for the options accepted by `isSafeUrl`.
- **`isPrivateIPv4(address)`** — Synchronous check for private/special-purpose IPv4 addresses.
- **`isPrivateIPv6(address)`** — Synchronous check for private/special-purpose IPv6 addresses.

## Installation

### NPM

```bash
npm install @tak-ps/node-safeurl
```

## Usage

```js
import fetch, { isSafeUrl, isPrivateIPv4, isPrivateIPv6 } from '@tak-ps/node-safeurl';
import { Type } from '@sinclair/typebox';

// SSRF-safe fetch — validates the URL and every redirect hop automatically
const res = await fetch('https://example.com/api/data');
const data = await res.typed(Type.Object({ id: Type.Number() }));

// Opt out of SSRF validation entirely for trusted internal calls
const internal = await fetch('http://localhost:3000/health', { safeUrl: false });

// Allow a specific private-network origin while keeping all other SSRF checks active
const api = await fetch('http://10.0.0.5:8080/api/status', {
    safeUrlAllow: ['http://10.0.0.5:8080'],
});

// Validate a URL manually before fetching
const result = await isSafeUrl('https://example.com/api');
if (result.safe) {
    // Safe to fetch
    const response = await fetch(result.url);
} else {
    console.error('Blocked:', result.reason);
}

// Validate a URL while allowing a known private endpoint
const result2 = await isSafeUrl('http://192.168.1.10/health', {
    allow: ['192.168.1.10'],
});

// Check individual IPs
isPrivateIPv4('192.168.1.1');  // true
isPrivateIPv4('8.8.8.8');      // false
isPrivateIPv6('::1');          // true
isPrivateIPv6('2606:4700:4700::1111'); // false
```

## API

### `fetch(input, init?): Promise<TypedResponse>`

SSRF-safe drop-in replacement for the global `fetch`. Validates the initial URL and every redirect destination against `isSafeUrl` before the request is made. Throws an `Err(403)` if a URL is deemed unsafe.

`init` accepts all standard `RequestInit` options plus:
- `safeUrl` (`boolean`, default `true`) — set to `false` to skip all SSRF validation (e.g. for fully trusted internal endpoints).
- `safeUrlAllow` (`string[]`, default `[]`) — list of origins (e.g. `"http://10.0.0.5:8080"`) or bare hostnames (e.g. `"10.0.0.5"`) that bypass SSRF checks while all other URLs remain validated. Use this instead of `safeUrl: false` when only specific private-network endpoints need to be exempted.

Custom `dispatcher` options are rejected when `safeUrl` is `true` because they can bypass SSRF protection.

### `TypedResponse`

Subclass of `Response` returned by `fetch`. Adds:

#### `.typed<T>(schema: TSchema): Promise<Static<T>>`

Parses the response body as JSON and validates it against a [TypeBox](https://github.com/sinclairzx81/typebox) schema. Throws `Err(500)` if validation fails.

```js
const res = await fetch('https://api.example.com/user/1');
const user = await res.typed(Type.Object({
    id: Type.Number(),
    name: Type.String(),
}));
```

### `FetchInit`

TypeScript interface extending `RequestInit` with additional fields:

```ts
interface FetchInit extends RequestInit {
    safeUrl?: boolean;      // default: true — set false to skip all SSRF checks
    safeUrlAllow?: string[]; // origins or hostnames exempt from SSRF checks
}
```

### `isSafeUrl(href: string, opts?: SafeUrlOptions): Promise<{ safe: boolean; url?: URL; reason?: string }>`

Validates that a URL is safe to fetch from a server context. Returns an object with:
- `safe` — `true` if the URL is safe, `false` if it should be blocked
- `url` — The parsed `URL` object (when the URL could be parsed)
- `reason` — A human-readable string explaining why the URL was blocked

`opts` accepts:
- `allow` (`string[]`) — origins (e.g. `"http://10.0.0.5:8080"`) or bare hostnames that are unconditionally considered safe, bypassing all checks below.

Checks performed (when not matched by `allow`):
1. URL must be parseable
2. Protocol must be `http:` or `https:`
3. Hostname must not be `localhost` or `0.0.0.0`
4. IP literal hostnames must not be in private/special-purpose ranges
5. DNS resolution results must not map to private/special-purpose IPs

### `SafeUrlOptions`

```ts
interface SafeUrlOptions {
    allow?: string[]; // origins or hostnames exempt from all SSRF checks
}
```

### `isPrivateIPv4(hostname: string): boolean`

Returns `true` if the given string is a valid IPv4 address in a private or special-purpose range.

### `isPrivateIPv6(address: string): boolean`

Returns `true` if the given string is a valid IPv6 address in a private or special-purpose range.

## Blocked Ranges

The following ranges are blocked (via `@microsoft/antissrf`):

- **IPv4**: Loopback (127.0.0.0/8), RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), Link-local (169.254.0.0/16), CGNAT (100.64.0.0/10), and more
- **IPv6**: Loopback (::1/128), ULA (fc00::/7), Link-local (fe80::/10), IPv4-mapped (::ffff:0:0/96), and more

## License

MIT
