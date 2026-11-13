import assert from 'node:assert/strict';
import { mkdtemp, rm, rmdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
const esp = { schema: 'xcim-doctor/esp-snapshot/v1', observedAt: snapshot.observedAt,
  credentialsEnabled: true, listValidationEnabled: true, eligibleRole: true, mfaRequired: false,
  partnerIdentityActive: true, delegationAvailable: true };

async function snapshotFile(t, data) {
  const folder = await mkdtemp(join(tmpdir(), 'xcim-doctor-test-'));
  const file = join(folder, 'snapshot.json');
  t.after(async () => { await rm(file, { force: true }); await rmdir(folder); });
  await writeFile(file, JSON.stringify({ ...data, observedAt: new Date().toISOString() }));
  return file;
}

test('parses a compatible attester origin without forwarding auth or URL components', () => {
  assert.equal(parseArgs(['doctor', '--attester', 'https://OTHER.example/']).origin, 'https://other.example');
  for (const value of ['https://u:p@other.example', 'https://other.example/a', 'http://other.example',
    'https://other.example?token=x', 'https://127.0.0.1', 'https://other.example\n']) {
    assert.throws(() => parseArgs(['doctor', '--attester', value]));
  }
  assert.throws(() => parseArgs(['doctor', '--attester', 'https://other.example', '--snapshot', 'setup.json']));
  for (const flags of [['--workflow', 'other'], ['--workflow', 'esp', '--attester', 'https://other.example'],
    ['--workflow', 'esp', '--profile', 'oidc'], ['--workflow', 'esp', '--intent', 'test'],
    ['--intent', 'test', '--profile', 'evp']]) assert.throws(() => parseArgs(['doctor', ...flags]));
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
  assert.equal(report.not_checked.includes('site_managed_oidc_setup'), true);
  assert.match(report.notes[0], /Emabled-hosted relay, not site-managed OIDC/);
  const evpOnly = diagnose(parseArgs(['doctor', '--profile', 'evp']), caps, snapshot, 'fresh', 'observed');
  assert.deepEqual(evpOnly.notes, []);
  assert.equal(evpOnly.not_checked.includes('site_managed_oidc_setup'), false);
  assert.equal(Object.hasOwn(report, 'ready'), false);
});

test('versioned exports have exact allowlists without breaking legacy snapshots', () => {
  const company = { schema: 'xcim-doctor/company-snapshot/v1', ...snapshot };
  assert.equal(inspectSnapshot(company, now), 'fresh');
  assert.equal(inspectSnapshot({ ...company, sessionToken: 'should-not-be-in-export' }, now), 'invalid');
  assert.equal(inspectSnapshot({ ...company, sources: [{ ...source, siteUrl: 'https://example.org' }] }, now), 'invalid');
  assert.equal(inspectSnapshot({ ...snapshot, organizationId: 'ignored-legacy-extra' }, now), 'fresh');
  assert.equal(inspectSnapshot(esp, now), 'invalid');
  assert.equal(inspectSnapshot(company, now, 'esp'), 'invalid');
  assert.equal(inspectSnapshot(esp, now, 'esp'), 'fresh');
  assert.equal(inspectSnapshot({ ...esp, schema: 'xcim-doctor/esp-snapshot/v2' }, now, 'esp'), 'invalid');
  assert.equal(inspectSnapshot({ ...esp, eligibleRole: 'true' }, now, 'esp'), 'invalid');
  assert.equal(inspectSnapshot({ ...esp, partnerId: 'esp_example' }, now, 'esp'), 'invalid');
  assert.equal(inspectSnapshot({ ...esp, credentialsEnabled: undefined }, now, 'esp'), 'invalid');
  assert.equal(inspectSnapshot(esp, now + 86400000, 'esp'), 'stale');
  assert.equal(inspectSnapshot({ ...esp, observedAt: '2026-11-12T12:00:00+00:60' }, now, 'esp'), 'invalid');
});

test('versioned company snapshot diagnoses the actual selected source, not an inventory', () => {
  const second = { ...source, sourceId: 'src_second', applicationId: null };
  const company = { schema: 'xcim-doctor/company-snapshot/v1', ...snapshot, sources: [source, second],
    selectedSourceId: source.sourceId, nextSourceCursor: 'src_second' };
  assert.equal(inspectSnapshot(company, now), 'fresh');
  assert.equal(inspectSnapshot({ ...company, selectedSourceId: 'src_not_in_file' }, now), 'invalid');
  assert.equal(inspectSnapshot({ ...company, selectedSourceId: [source.sourceId] }, now), 'invalid');
  const args = ['doctor', '--snapshot', 'setup.json'];
  const selected = diagnose(parseArgs(args), caps, company, 'fresh', 'observed');
  assert.equal(selected.snapshot.source_id, source.sourceId);
  assert.equal(check(selected, 'source.binding').status, 'configured');
  const override = diagnose(parseArgs([...args, '--source', second.sourceId]), caps, company, 'fresh', 'observed');
  assert.equal(override.snapshot.source_id, second.sourceId);
  assert.equal(check(override, 'source.binding').status, 'missing');
  const missingOverride = diagnose(parseArgs([...args, '--source', 'src_other']), caps, company, 'fresh', 'observed');
  assert.equal(check(missingOverride, 'source.binding').next_action, 'export_setup_page_containing_source');
  const noSelection = { ...company, sources: [], selectedSourceId: null, nextSourceCursor: null };
  assert.equal(inspectSnapshot(noSelection, now), 'fresh');
  const incomplete = diagnose(parseArgs(args), caps, noSelection, 'fresh', 'observed');
  assert.equal(check(incomplete, 'source.binding').status, 'unknown');
});

test('versioned OIDC exchange check is scoped to the selected site and current key', () => {
  const company = { schema: 'xcim-doctor/company-snapshot/v1', ...snapshot, selectedSourceId: source.sourceId };
  const opts = parseArgs(['doctor', '--profile', 'oidc']);
  for (const [row, expected] of [[{ ...source, exchangeEndpointVerified: true }, 'configured'],
    [{ ...source, exchangeEndpointVerified: false }, 'missing'], [{ ...source, exchangeEndpointVerified: null }, 'unknown'],
    [source, 'unknown']]) {
    const versioned = { ...company, exchangeEndpointActive: true, sources: [row] };
    assert.equal(inspectSnapshot(versioned, now), 'fresh');
    assert.equal(check(diagnose(opts, caps, versioned, 'fresh', 'observed'), 'oidc.exchange_endpoint').status, expected);
  }
  assert.equal(inspectSnapshot({ ...company, sources: [{ ...source, exchangeEndpointVerified: 'true' }] }, now), 'invalid');
  assert.equal(check(diagnose(opts, caps, snapshot, 'fresh', 'observed'), 'oidc.exchange_endpoint').status, 'configured');
});

test('connected OIDC with expired review is advisory unless testing', async (t) => {
  const connected = { ...snapshot, sources: [{ ...source, oauthBootstrapConfirmed: true }] };
  const file = await snapshotFile(t, connected);
  const args = ['doctor', '--profile', 'oidc', '--snapshot', file];
  const operate = await run(parseArgs(args), async () => caps);
  const review = check(operate.report, 'oidc.provider_review');
  assert.deepEqual(review, { id: 'oidc.provider_review', status: 'missing', evidence: 'console_snapshot',
    human_required: false, next_action: 'review_before_new_oidc_test', actor: 'attester_operator',
    severity: 'advisory', blocking: false });
  assert.equal(operate.code, 0);
  assert.equal(operate.report.summary.missing, 1);
  assert.equal(operate.report.summary.blocking, 0);
  assert.equal(operate.report.summary.advisory, 1);
  const testIntent = await run(parseArgs([...args, '--intent', 'test']), async () => caps);
  assert.equal(testIntent.code, 2);
  assert.equal(check(testIntent.report, 'oidc.provider_review').blocking, true);
  assert.equal(check(testIntent.report, 'oidc.provider_review').human_required, true);
  assert.equal(check(testIntent.report, 'oidc.provider_review').next_action, 'complete_authorized_provider_review');
  const notConnected = diagnose(parseArgs(args), caps, snapshot, 'fresh', 'observed');
  assert.equal(check(notConnected, 'oidc.provider_review').severity, 'blocker');
});

test('ESP diagnoses only snapshot facts and never uses the public transport', async (t) => {
  const file = await snapshotFile(t, esp);
  const opts = parseArgs(['doctor', '--workflow', 'esp', '--snapshot', file]);
  let called = false;
  const transport = async () => { called = true; throw new Error('must not fetch'); };
  const observed = await run(opts, transport);
  assert.equal(called, false);
  assert.equal(observed.code, 0);
  assert.equal(observed.report.capabilities, 'not_checked');
  assert.equal(observed.report.workflow, 'esp');
  assert.equal(observed.report.profile, null);
  assert.equal(observed.report.snapshot.application_id, null);
  assert.equal(observed.report.not_checked.includes('current_permission'), true);
  const blocked = diagnose(opts, undefined, { ...esp, mfaRequired: true, delegationAvailable: false }, 'fresh', 'not_checked');
  assert.equal(check(blocked, 'esp.mfa').actor, 'browser_user');
  assert.equal(check(blocked, 'esp.delegation').actor, 'company_admin');
  const partial = diagnose(opts, undefined, { ...esp, delegationAvailable: null }, 'fresh', 'not_checked');
  assert.equal(check(partial, 'esp.delegation').status, 'unknown');
  assert.equal(check(partial, 'esp.delegation').human_required, false);
  const absent = await run(parseArgs(['doctor', '--workflow', 'esp']), transport);
  assert.equal(absent.code, 2);
  assert.equal(called, false);
  assert.equal(absent.report.summary.human_required, 1);
  assert.equal(check(absent.report, 'setup.snapshot').next_action, 'export_esp_diagnostics_in_console');
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
