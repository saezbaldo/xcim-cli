import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diagnose, fetchCapabilities, inspectSnapshot, parseArgs, run } from '../xcim.mjs';

const caps = {
  protocol: 'xcim-0.1',
  consent: { hosted: true },
  identity_evidence: {
    supported_profiles: ['evp-01', 'oidc-01'],
    evp_01: { delivery_modes: { vendor_origin_handoff: { status: 'experimental' }, emabled_hosted: { status: 'unavailable' } } },
    oidc_01: { status: 'supported' }
  }
};
const app = 'urn:xcim:app:example';
const source = { sourceId: 'src_example', applicationId: app, domainVerificationRecorded: true,
  returnRegistered: true, oauthBindingActive: true, oauthReviewCurrent: false, oauthBootstrapConfirmed: null };
const snapshot = { applicationId: app, requestId: 'pr_example', requestStatus: 'active', registrationAvailable: true,
  manifestPublicationRecorded: true, exchangeEndpointActive: true, pairwiseKeyConfigured: true,
  observedAt: '2026-11-12T12:00:00.1234567Z', nextSourceCursor: null, sources: [source] };
const now = Date.parse('2026-11-12T13:00:00Z');
const check = (report, id) => report.checks.find((c) => c.id === id);

test('parses a compatible attester origin without forwarding auth or URL components', () => {
  assert.equal(parseArgs(['doctor', '--attester', 'https://OTHER.example/']).origin, 'https://other.example');
  for (const value of ['https://u:p@other.example', 'https://other.example/a', 'http://other.example',
    'https://other.example?token=x', 'https://127.0.0.1', 'https://other.example\n']) {
    assert.throws(() => parseArgs(['doctor', '--attester', value]));
  }
  assert.throws(() => parseArgs(['doctor', '--attester', 'https://other.example', '--snapshot', 'setup.json']));
});

test('requires fresh, well-shaped evidence; pagination never means absent', () => {
  assert.equal(inspectSnapshot(snapshot, now), 'fresh');
  assert.equal(inspectSnapshot(snapshot, now + 86400000), 'stale');
  assert.equal(inspectSnapshot({ ...snapshot, observedAt: '2026-02-30T00:00:00Z' }, now), 'invalid');
  assert.equal(inspectSnapshot({ ...snapshot, sources: [source, source] }, now), 'invalid');
  assert.equal(inspectSnapshot({ ...snapshot, registrationAvailable: 'false' }, now), 'invalid');
  const paged = { ...snapshot, sources: [], nextSourceCursor: 'src_other' };
  const report = diagnose(parseArgs(['doctor']), caps, paged, 'fresh', 'observed');
  assert.equal(check(report, 'source.binding').status, 'unknown');
});

test('separates advertised support, recorded configuration and required human review', () => {
  const report = diagnose(parseArgs(['doctor', '--evp-mode', 'hosted']), caps, snapshot, 'fresh', 'observed');
  assert.equal(check(report, 'evp.delivery_mode').status, 'missing');
  assert.equal(check(report, 'manifest.publication').status, 'configured');
  assert.equal(check(report, 'oidc.provider_review').status, 'missing');
  assert.equal(check(report, 'oidc.provider_review').human_required, true);
  assert.equal(check(report, 'oidc.bootstrap').status, 'unknown');
  assert.equal(report.not_checked.includes('current_permission'), true);
  assert.equal(Object.hasOwn(report, 'ready'), false);
});

test('public-only diagnosis remains unknown; offline mode never calls the transport', async () => {
  const publicOnly = await run(parseArgs(['doctor']), async () => caps);
  assert.equal(publicOnly.code, 2);
  assert.equal(check(publicOnly.report, 'manifest.publication').status, 'unknown');
  assert.equal(check(publicOnly.report, 'manifest.publication').human_required, false);
  assert.equal(publicOnly.report.summary.human_required, 1);
  let called = false;
  const offline = await run(parseArgs(['doctor', '--offline']), async () => { called = true; });
  assert.equal(offline.code, 2);
  assert.equal(called, false);
  const failed = await run(parseArgs(['doctor']), async () => { throw new Error('secret-like input'); });
  assert.equal(failed.code, 3);
  assert.equal(JSON.stringify(failed.report).includes('secret-like'), false);
});

test('network method, path, credential and redirect boundary', async (t) => {
  const original = globalThis.fetch;
  t.after(() => { globalThis.fetch = original; });
  globalThis.fetch = async (url, opts) => {
    assert.equal(url, 'https://api.emabled.com/v1/capabilities');
    assert.equal(opts.method, 'GET');
    assert.equal(opts.redirect, 'error');
    assert.equal(opts.credentials, 'omit');
    assert.deepEqual(opts.headers, { Accept: 'application/json' });
    return Response.json(caps);
  };
  assert.deepEqual(await fetchCapabilities('https://api.emabled.com'), caps);
  globalThis.fetch = async () => Response.redirect('https://another.example');
  await assert.rejects(fetchCapabilities('https://api.emabled.com'));
  globalThis.fetch = async () => Response.json({ padding: 'x'.repeat(256 * 1024) });
  await assert.rejects(fetchCapabilities('https://api.emabled.com'));
});
