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
        const firstError = errors.First();

        throw new Err(500, null, `Internal Validation Error: ${JSON.stringify(firstError)}`);
    }
}

export default async function (
    input: RequestInfo,
    init?: FetchInit,
): Promise<TypedResponse> {
    const { safeUrl = true, ...fetchInit } = init ?? {};

    if (safeUrl) {
        const check = await isSafeUrl(input.toString());
        if (!check.safe) {
            throw new Err(403, null, `Unsafe URL: ${check.reason}`);
        }
    }

    return new TypedResponse(await fetch(input, fetchInit));
}
