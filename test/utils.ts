import { Response } from 'undici';
import { TypedResponse } from '../lib/fetch.js';

export function makeTypedResponse(body: unknown, status = 200): TypedResponse {
    const raw = new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    });
    return new TypedResponse(raw);
}
