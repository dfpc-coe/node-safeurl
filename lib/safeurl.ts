import { lookup } from 'node:dns/promises';
import { IPAddressRanges } from '@microsoft/antissrf';
import ipaddr from 'ipaddr.js';

// Pre-built (CIDR, parsed-range) pairs from Microsoft's maintained SSRF-prevention
// IP address database.  Covers loopback, RFC 1918, link-local, CGNAT, ULA,
// multicast, and all other special-purpose address blocks.
// Kept current by updating @microsoft/antissrf.
interface BlockEntry {
    cidr: string;
    range: [ipaddr.IPv4 | ipaddr.IPv6, number];
}

const blocked: BlockEntry[] = IPAddressRanges.recommendedLatest
    .map((cidr) => {
        try {
            const r = ipaddr.parseCIDR(cidr);
            return { cidr, range: r };
        } catch {
            return null;
        }
    })
    .filter((e): e is BlockEntry => e !== null);

/** Returns true when `address` matches any blocked (private/special-purpose) CIDR. */
function isBlockedIP(address: string): boolean {
    let parsed: ipaddr.IPv4 | ipaddr.IPv6;
    try {
        parsed = ipaddr.parse(address);
    } catch {
        return false;
    }

    // If the address is an IPv4-mapped IPv6 (::ffff:x.x.x.x), unwrap to IPv4
    // so it can be checked against IPv4 CIDR ranges.
    if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
        parsed = (parsed as ipaddr.IPv6).toIPv4Address();
    }

    for (const entry of blocked) {
        // Only compare within the same address family
        if (entry.range[0].kind() !== parsed.kind()) continue;
        if (parsed.match(entry.range)) return true;
    }
    return false;
}

/**
 * Returns true for IPv4 addresses that fall in private / special-purpose ranges.
 * Delegates to `@microsoft/antissrf` `IPAddressRanges.recommendedLatest`.
 */
export function isPrivateIPv4(hostname: string): boolean {
    // Must be exactly four segments; each must be non-empty, numeric, and within 0–255.
    // Number() normalizes whitespace-padded and zero-prefixed strings (e.g. "01" → 1,
    // "  10  " → 10), which handles forms that ipaddr.parse() would otherwise reject.
    const segments = hostname.split('.');
    if (segments.length !== 4) return false;
    const parts = segments.map(Number);
    if (parts.some((p, i) => segments[i].trim() === '' || Number.isNaN(p) || p < 0 || p > 255)) return false;
    return isBlockedIP(parts.join('.'));
}

/**
 * Returns true for IPv6 addresses that fall in private / special-purpose ranges.
 * Delegates to `@microsoft/antissrf` `IPAddressRanges.recommendedLatest`.
 */
export function isPrivateIPv6(address: string): boolean {
    // Strip zone ID (e.g. %eth0) and normalise to lowercase
    const addr = address.toLowerCase().split('%')[0];
    if (!addr.includes(':')) return false;
    return isBlockedIP(addr);
}

export async function isSafeUrl(href: string): Promise<{ safe: boolean; url?: URL; reason?: string }> {
    let url: URL;
    try {
        url = new URL(href);
    } catch {
        return { safe: false, reason: `invalid URL: ${href}` };
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { safe: false, url, reason: `unsupported protocol: ${url.protocol}` };
    }

    // Strip IPv6 brackets and any trailing dot (trailing dot is valid per DNS but bypasses
    // literal hostname checks — e.g. "localhost." has the same meaning as "localhost").
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

    // Block known-bad hostname literals, including all subdomains of localhost
    // (modern OS resolvers route *.localhost to 127.0.0.1).
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '0.0.0.0') {
        return { safe: false, url, reason: `blocked hostname: ${hostname}` };
    }

    // Block private / special-purpose IP literals via the antissrf block list.
    // This catches addresses like 127.0.0.1, 10.x.x.x, 192.168.x.x, fc00::, ::1, etc.
    if (isBlockedIP(hostname)) {
        return { safe: false, url, reason: `blocked IP address: ${hostname}` };
    }

    // Resolve the hostname via DNS and reject any result that maps to a private address.
    // This guards against SSRF via public-looking hostnames that resolve to internal IPs.
    // Fail open on DNS errors so that unreachable-but-legitimate hosts are not silently
    // blocked; the subsequent fetch will surface any connectivity issues on its own.
    try {
        const records = await lookup(hostname, { all: true });
        for (const { address } of records) {
            if (isBlockedIP(address)) {
                return { safe: false, url, reason: `hostname resolves to blocked IP: ${address}` };
            }
        }
    } catch {
        // DNS lookup failed (NXDOMAIN, no network) — allow and let the fetch fail
    }

    return { safe: true, url };
}
