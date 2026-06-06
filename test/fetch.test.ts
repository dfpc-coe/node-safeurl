import test from 'node:test';
import assert from 'node:assert';
import { Type } from '@sinclair/typebox';
import { Response } from 'undici';
import safeFetch, { TypedResponse } from '../lib/fetch.js';
import { makeTypedResponse } from './utils.js';

test('safeFetch — rejects unsafe URLs by default', async (t) => {
    await t.test('rejects private IPv4 address', async () => {
        await assert.rejects(
            () => safeFetch('http://192.168.1.1/'),
            (err: Error) => {
                assert.ok(err.message.includes('Unsafe URL'));
                return true;
            },
        );
    });

    await t.test('rejects loopback address', async () => {
        await assert.rejects(
            () => safeFetch('http://127.0.0.1/'),
            (err: Error) => {
                assert.ok(err.message.includes('Unsafe URL'));
                return true;
            },
        );
    });

    await t.test('rejects URL object pointing to private range', async () => {
        await assert.rejects(
            () => safeFetch(new URL('http://10.0.0.1/')),
            (err: Error) => {
                assert.ok(err.message.includes('Unsafe URL'));
                return true;
            },
        );
    });
});

test('safeFetch — safeUrl: false bypasses SSRF check', async () => {
    await assert.rejects(
        () => safeFetch('http://127.0.0.1/', { safeUrl: false }),
        (err: Error) => {
            assert.ok(!err.message.includes('Unsafe URL'), 'should not be an SSRF guard error');
            return true;
        },
    );
});

test('safeFetch — rejects redirect to private address', async () => {
    const { isSafeUrl } = await import('../lib/safeurl.js');
    const check = await isSafeUrl('http://192.168.0.1/');
    assert.strictEqual(check.safe, false, 'private redirect target must be detected as unsafe');
});

test('safeFetch — rejects custom dispatcher when safeUrl is enabled', async () => {
    const { MockAgent } = await import('undici');
    const agent = new MockAgent();
    await assert.rejects(
        () => safeFetch('http://example.com/', { dispatcher: agent }),
        (err: Error) => {
            assert.ok(err.message.includes('Custom dispatchers are not permitted'));
            return true;
        },
    );
});

test('safeFetch — allows custom dispatcher when safeUrl is disabled', async () => {
    const { MockAgent } = await import('undici');
    const agent = new MockAgent();
    agent.disableNetConnect();
    const client = agent.get('http://example.com');
    client.intercept({ path: '/', method: 'GET' }).reply(200, '{}');
    const res = await safeFetch('http://example.com/', { safeUrl: false, dispatcher: agent });
    assert.strictEqual(res.status, 200);
    await agent.close();
});

test('TypedResponse — preserves wrapped response url', () => {
    const raw = new Response('{}', { status: 200 });
    const typed = new TypedResponse(raw);
    assert.strictEqual(typed.url, raw.url);
});

test('TypedResponse.typed() — valid body matches schema', async () => {
    const Schema = Type.Object({
        name: Type.String(),
        age: Type.Number(),
    });

    const payload = { name: 'Alice', age: 30 };
    const res = makeTypedResponse(payload);
    const result = await res.typed(Schema);
    assert.deepStrictEqual(result, payload);
});

test('TypedResponse.typed() — invalid body throws validation error', async () => {
    const Schema = Type.Object({
        name: Type.String(),
        age: Type.Number(),
    });

    const bad = { name: 'Bob', age: 'not-a-number' };
    const res = makeTypedResponse(bad);
    await assert.rejects(
        () => res.typed(Schema),
        (err: Error) => {
            assert.ok(err.message.includes('Internal Validation Error'));
            return true;
        },
    );
});

test('TypedResponse.typed() — reuses compiled schema cache', async () => {
    const Schema = Type.Object({ id: Type.Number() });

    const res1 = makeTypedResponse({ id: 1 });
    const res2 = makeTypedResponse({ id: 2 });

    assert.deepStrictEqual(await res1.typed(Schema), { id: 1 });
    assert.deepStrictEqual(await res2.typed(Schema), { id: 2 });
});
