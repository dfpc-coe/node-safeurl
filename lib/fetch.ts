import Err from '@openaddresses/batch-error';
import type { Static, TSchema, TUnknown } from '@sinclair/typebox';
import { TypeCompiler } from '@sinclair/typebox/compiler';
import { fetch, Response } from 'undici';
import type { RequestInfo, RequestInit } from 'undici';
import { isSafeUrl } from './safeurl.js';

const cache = new WeakMap<TSchema, ReturnType<typeof TypeCompiler.Compile>>();

export interface FetchInit extends RequestInit {
    /** Set to false to disable SSRF-safe URL validation. Defaults to true. */
    safeUrl?: boolean;
}

export class TypedResponse extends Response {
    constructor(response: Response) {
        super(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
        });
        const originalUrl = response.url;
        Object.defineProperty(this, 'url', {
            get: () => originalUrl,
            enumerable: true,
            configurable: true,
        });
    }

    typed<T extends TSchema>(type: T): Promise<Static<T>>;

    async typed<T extends TSchema = TUnknown>(type: T): Promise<Static<T>> {
        const body = await this.json();

        const cached = cache.get(type);

        let typeChecker;

        if (cached) {
            typeChecker = cached;
        } else {
            typeChecker = TypeCompiler.Compile(type);
            cache.set(type, typeChecker);
        }

        const result = typeChecker.Check(body);

        if (result) return body;

        const errors = typeChecker.Errors(body);
        const firstError = errors[Symbol.iterator]().next().value ?? null;
        throw new Err(500, null, `Internal Validation Error: ${JSON.stringify(firstError ?? null)}`);
    }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 10;

function extractHref(input: RequestInfo): string {
    if (typeof input === 'string') return input;
    if (input instanceof URL) return input.href;
    return (input as { url?: string }).url ?? input.toString();
}

export default async function (
    input: RequestInfo,
    init?: FetchInit,
): Promise<TypedResponse> {
    const { safeUrl = true, ...fetchInit } = init ?? {};

    if (safeUrl) {
        // Reject custom dispatchers: they can route requests to arbitrary internal
        // services regardless of what URL was validated, bypassing SSRF protection.
        if ('dispatcher' in fetchInit) {
            throw new Err(403, null, 'Custom dispatchers are not permitted when safeUrl is enabled');
        }

        // Validate the initial URL.
        const check = await isSafeUrl(extractHref(input));
        if (!check.safe) {
            throw new Err(403, null, `Unsafe URL: ${check.reason}`);
        }

        // Follow redirects manually so each hop is re-validated against isSafeUrl,
        // preventing SSRF via a public URL that 30x-redirects to an internal address.
        const callerRedirect = fetchInit.redirect;
        fetchInit.redirect = 'manual';

        let currentInput: RequestInfo = input;
        let hops = 0;

        while (true) {
            const response = await fetch(currentInput, fetchInit);

            if (!REDIRECT_STATUSES.has(response.status) || callerRedirect === 'manual') {
                return new TypedResponse(response);
            }

            if (callerRedirect === 'error') {
                throw new Err(400, null, 'Redirects are not allowed');
            }

            if (++hops > MAX_REDIRECTS) {
                throw new Err(400, null, 'Too many redirects');
            }

            const location = response.headers.get('location');
            if (!location) {
                return new TypedResponse(response);
            }

            // Resolve relative Location headers against the current request URL.
            const resolved = new URL(location, extractHref(currentInput)).href;
            const locationCheck = await isSafeUrl(resolved);
            if (!locationCheck.safe) {
                throw new Err(403, null, `Unsafe redirect URL: ${locationCheck.reason}`);
            }

            // For 303, switch to GET for non-GET/HEAD methods. For 301/302, switch to GET only for POST.
            const method = (fetchInit.method ?? 'GET').toUpperCase();
            const switchToGet =
                (response.status === 303 && method !== 'GET' && method !== 'HEAD') ||
                ((response.status === 301 || response.status === 302) && method === 'POST');

            if (switchToGet) {
                fetchInit.method = 'GET';
                fetchInit.body = undefined;
            }

            currentInput = resolved;
        }
    }

    return new TypedResponse(await fetch(input, fetchInit));
}
