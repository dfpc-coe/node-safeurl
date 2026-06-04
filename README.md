<h1 align=center>Node-SafeURL</h1>

<p align=center>SSRF-safe URL validation library for Node.js</p>

Lightweight TypeScript library for validating URLs to prevent Server-Side Request Forgery (SSRF) attacks. It blocks requests to private IP ranges, localhost, link-local addresses, and other special-purpose networks using Microsoft's maintained [`@microsoft/antissrf`](https://www.npmjs.com/package/@microsoft/antissrf) block lists.

## About

`node-safeurl` provides three main exports:

- **`isSafeUrl(url)`** — Async function that validates a URL is safe to fetch. Checks protocol, hostname, IP literals, and performs DNS resolution to guard against DNS rebinding attacks.
- **`isPrivateIPv4(address)`** — Synchronous check for private/special-purpose IPv4 addresses.
- **`isPrivateIPv6(address)`** — Synchronous check for private/special-purpose IPv6 addresses.

## Installation

### NPM

```bash
npm install @tak-ps/node-safeurl
```

## Usage

```js
import { isSafeUrl, isPrivateIPv4, isPrivateIPv6 } from '@tak-ps/node-safeurl';

// Validate a URL before fetching
const result = await isSafeUrl('https://example.com/api');
if (result.safe) {
    // Safe to fetch
    const response = await fetch(result.url);
} else {
    console.error('Blocked:', result.reason);
}

// Check individual IPs
isPrivateIPv4('192.168.1.1');  // true
isPrivateIPv4('8.8.8.8');      // false
isPrivateIPv6('::1');          // true
isPrivateIPv6('2606:4700:4700::1111'); // false
```

## API

### `isSafeUrl(href: string): Promise<{ safe: boolean; url?: URL; reason?: string }>`

Validates that a URL is safe to fetch from a server context. Returns an object with:
- `safe` — `true` if the URL is safe, `false` if it should be blocked
- `url` — The parsed `URL` object (when the URL could be parsed)
- `reason` — A human-readable string explaining why the URL was blocked

Checks performed:
1. URL must be parseable
2. Protocol must be `http:` or `https:`
3. Hostname must not be `localhost` or `0.0.0.0`
4. IP literal hostnames must not be in private/special-purpose ranges
5. DNS resolution results must not map to private/special-purpose IPs

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
