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

/**
 * Options for `isSafeUrl`.
 */
export interface SafeUrlOptions {
    /**
     * Explicit list of origins (e.g. `["http://internal-api:8080"]`) or bare
     * hostnames (e.g. `["internal-api"]`) that are always considered safe,
     * bypassing the SSRF block-list and DNS checks.  Use this to allow known
     * private-network endpoints that the caller has already authorised.
     */
    allow?: string[];
}

/**
 * Extracts the hostname from an allow-list entry.
 * For origin-style entries (those containing `://`) the hostname is parsed from the URL.
 * For bare-hostname entries the value is normalised directly.
 * Returns `null` when the entry cannot be parsed.
 */
function extractAllowedHostname(entry: string): string | null {
    if (entry.includes('://')) {
        try {
            return new URL(entry).hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
        } catch {
            return null;
        }
    }
    const h = entry.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    return h || null;
}

/**
 * Resolves every hostname extracted from the allow list to its DNS addresses.
 * IP literals are added directly without a DNS round-trip.
 * Used as a last-resort check when the URL hostname resolves to a blocked IP
 * but may be a DNS alias or port-variant of an explicitly-allowed internal host.
 */
async function resolveAllowedIPs(allow: string[]): Promise<Set<string>> {
    const ips = new Set<string>();

    await Promise.allSettled(allow.map(async (entry) => {
        const allowedHostname = extractAllowedHostname(entry);
        if (!allowedHostname) return;

        // If the allow entry is already an IP literal, record it directly.
        try {
            ips.add(ipaddr.parse(allowedHostname).toString());
            return;
        } catch {
            // Not an IP literal — fall through to DNS resolution.
        }

        try {
            const records = await lookup(allowedHostname, { all: true });
            for (const r of records) ips.add(r.address);
        } catch {
            // DNS lookup failed for the allowed hostname; silently skip it.
        }
    }));

    return ips;
}

export async function isSafeUrl(href: string, opts: SafeUrlOptions = {}): Promise<{ safe: boolean; url?: URL; reason?: string }> {
    let url: URL;
    try {
        url = new URL(href);
    } catch {
        return { safe: false, reason: `invalid URL: ${href}` };
    }

    // Explicit allow-list check: if the URL's origin or hostname exactly matches
    // any entry in `allow`, skip all SSRF checks and return safe immediately.
    if (opts.allow && opts.allow.length > 0) {
        for (const entry of opts.allow) {
            // Treat entries that look like origins (contain ://) as full-origin matches,
            // otherwise treat them as bare hostname matches.
            if (entry.includes('://')) {
                let allowedOrigin: string;
                try {
                    allowedOrigin = new URL(entry).origin;
                } catch {
                    continue;
                }
                if (url.origin === allowedOrigin) return { safe: true, url };
            } else {
                const allowedHost = entry.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
                const urlHost = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
                if (urlHost === allowedHost) return { safe: true, url };
            }
        }
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { safe: false, url, reason: `unsupported protocol: ${url.protocol}` };
    }

    // Strip IPv6 brackets, any trailing dot, and any zone ID (e.g. %eth0 or percent-encoded
    // %25eth0). Zone IDs are valid in IPv6 link-local syntax but ipaddr.js cannot parse the
    // percent-encoded form, causing isBlockedIP() to return false and silently allowing
    // addresses like fe80::1%25eth0 through the block-list check.
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/g, '').split('%')[0];

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
        // Resolved lazily — only populated when a blocked IP is encountered and
        // the caller supplied an allow list.
        let allowedIPs: Set<string> | null = null;
        for (const { address } of records) {
            if (isBlockedIP(address)) {
                // Before rejecting, check whether this blocked IP is one that an
                // allow-list hostname resolves to.  This handles cases where the URL
                // uses a different port or is a DNS alias of an explicitly-allowed
                // internal host (e.g. allow=['http://media'] but URL is http://media:9997).
                if (opts.allow && opts.allow.length > 0) {
                    if (!allowedIPs) allowedIPs = await resolveAllowedIPs(opts.allow);
                    if (allowedIPs.has(address)) continue;
                }
                return { safe: false, url, reason: `hostname resolves to blocked IP: ${address}` };
            }
        }
    } catch {
        // DNS lookup failed (NXDOMAIN, no network) — allow and let the fetch fail
    }

    return { safe: true, url };
}
