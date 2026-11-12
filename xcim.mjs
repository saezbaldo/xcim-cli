#!/usr/bin/env node
import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const LIMIT = 256 * 1024;
const SCHEMA = 'xcim-doctor/v1';
const USAGE = 'xcim doctor [--attester emabled|https://host] [--profile evp|oidc|both] [--evp-mode vendor|hosted] [--snapshot FILE [--source src_ID]] [--offline] [--json]';
const APP = /^urn:xcim:app:[A-Za-z0-9._~-]{1,54}$/;
const SOURCE = /^src_[A-Za-z0-9_-]{4,43}$/;
const REQUEST = /^pr_[A-Za-z0-9_-]{5,44}$/;
const DATE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$/;
const APP_FIELDS = ['manifestPublicationRecorded', 'exchangeEndpointActive', 'pairwiseKeyConfigured'];
const SOURCE_FIELDS = ['domainVerificationRecorded', 'returnRegistered', 'oauthBindingActive', 'oauthReviewCurrent', 'oauthBootstrapConfirmed'];
const REQUEST_STATES = ['pending_review', 'approved', 'provisioning', 'active', 'rejected', 'suspended', 'failed'];
const record = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const matches = (v, re) => typeof v === 'string' && v.trim() === v && re.test(v);
const nullableBooleans = (v, fields) => fields.every((key) => v[key] === null || typeof v[key] === 'boolean');
const state = (v) => v === true ? 'configured' : v === false ? 'missing' : 'unknown';
const fail = () => { throw new Error('invalid input'); };
const decode = (b) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));

export function parseArgs(argv) {
  if (argv[0] !== 'doctor') fail();
  const opts = { attester: 'emabled', profile: 'both', 'evp-mode': 'vendor' };
  const used = new Set();
  for (let i = 1; i < argv.length; i++) {
    const key = argv[i].slice(2);
    if (!argv[i].startsWith('--') || used.has(key)) fail();
    used.add(key);
    if (['json', 'offline'].includes(key)) opts[key] = true;
    else if (['attester', 'profile', 'evp-mode', 'snapshot', 'source'].includes(key)) {
      const value = argv[++i];
      if (!value || value.startsWith('--')) fail();
      opts[key] = value;
    } else fail();
  }
  if (!['evp', 'oidc', 'both'].includes(opts.profile) || !['vendor', 'hosted'].includes(opts['evp-mode'])) fail();
  if (opts.source && (!opts.snapshot || !matches(opts.source, SOURCE))) fail();
  if (opts.attester === 'emabled') opts.origin = 'https://api.emabled.com';
  else {
    const match = /^https:\/\/([a-z0-9.-]+)\/?$/i.exec(opts.attester);
    const labels = match?.[1].toLowerCase().split('.') ?? [];
    if (!match || match[0] !== opts.attester || labels.length < 2 || match[1].length > 253 ||
        !/^[a-z]/.test(labels.at(-1)) ||
        labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) fail();
    opts.origin = 'https://' + labels.join('.');
    opts.attester = opts.origin === 'https://api.emabled.com' ? 'emabled' : 'custom';
    if (opts.snapshot && opts.attester === 'custom') fail();
  }
  return opts;
}

function loadSnapshot(path) {
  if (/^(?:[\\/]{2}|[a-z]+:\/\/)/i.test(path) || !lstatSync(path).isFile()) fail();
  const fd = openSync(path, 'r');
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > LIMIT) fail();
    const buf = Buffer.alloc(LIMIT + 1);
    let size = 0;
    while (size < buf.length) {
      const read = readSync(fd, buf, size, buf.length - size, null);
      if (!read) break;
      size += read;
    }
    if (size > LIMIT) fail();
    return decode(buf.subarray(0, size));
  } finally { closeSync(fd); }
}

export function inspectSnapshot(data, now = Date.now()) {
  if (!record(data) || !matches(data.applicationId, APP) || !matches(data.requestId, REQUEST) ||
      !REQUEST_STATES.includes(data.requestStatus) || typeof data.registrationAvailable !== 'boolean' ||
      (data.registrationAvailable && data.requestStatus !== 'active') ||
      !nullableBooleans(data, APP_FIELDS) || !matches(data.observedAt, DATE) ||
      !Array.isArray(data.sources) || data.sources.length > 25 ||
      (data.nextSourceCursor !== null && !matches(data.nextSourceCursor, SOURCE))) return 'invalid';
  const ids = new Set();
  for (const row of data.sources) {
    if (!record(row) || !matches(row.sourceId, SOURCE) || ids.has(row.sourceId) ||
        (row.applicationId !== null && !matches(row.applicationId, APP)) ||
        !nullableBooleans(row, SOURCE_FIELDS)) return 'invalid';
    ids.add(row.sourceId);
  }
  const [year, month, day, hour, minute, second] = data.observedAt.slice(0, 19).split(/[-T:]/).map(Number);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  if (!year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day ||
      hour > 23 || minute > 59 || second > 59) return 'invalid';
  const time = Date.parse(data.observedAt);
  if (!Number.isFinite(time) || time > now + 300000) return 'invalid';
  return now - time > 86400000 ? 'stale' : 'fresh';
}

function capabilityState(caps, profile, mode) {
  if (!caps) return null;
  const identity = caps.identity_evidence;
  const status = profile === 'oidc' ? identity.oidc_01?.status
    : identity.evp_01?.delivery_modes?.[mode === 'vendor' ? 'vendor_origin_handoff' : 'emabled_hosted']?.status;
  if (status === 'unavailable') return false;
  if (['supported', 'experimental'].includes(status) && identity.supported_profiles.includes(profile + '-01')) return true;
  return null;
}

export function diagnose(opts, caps, data, snapshotStatus, capabilitiesStatus) {
  const checks = [];
  const add = (id, status, evidence, next_action, human = false) =>
    checks.push({ id, status, evidence, human_required: human && status !== 'configured',
      next_action: status === 'configured' ? null : next_action });
  const publicCheck = (id, value, action) => add(id, state(value), 'attester_capabilities', action);
  const privateCheck = (id, value, action) => {
    if (value == null && id !== 'setup.snapshot' && id !== 'source.binding') {
      add(id, 'unknown', 'console_snapshot', snapshotStatus === 'fresh'
        ? 'inspect_setup_prerequisites' : 'provide_setup_snapshot');
      return;
    }
    const human = value === false || id === 'setup.snapshot' || action === 'export_setup_page_containing_source';
    add(id, state(value), 'console_snapshot', action, human);
  };
  const evp = opts.profile !== 'oidc';
  const oidc = opts.profile !== 'evp';
  publicCheck('consent.hosted', caps?.consent?.hosted, 'check_attester_capabilities');
  if (evp) publicCheck('evp.delivery_mode', capabilityState(caps, 'evp', opts['evp-mode']), 'choose_supported_evp_mode');
  if (oidc) publicCheck('oidc.support', capabilityState(caps, 'oidc'), 'check_oidc_availability');
  const setup = snapshotStatus === 'fresh' ? data : null;
  privateCheck('setup.snapshot', setup ? true : null, 'export_current_setup_in_console');
  const requestActions = { pending_review: 'approve_request_in_workspace', approved: 'await_operator_provisioning',
    provisioning: 'await_operator_provisioning', rejected: 'review_rejected_request',
    suspended: 'review_suspended_application', failed: 'review_provisioning_failure' };
  privateCheck('application.registration', setup?.registrationAvailable,
    requestActions[setup?.requestStatus] ?? 'check_application_registration');
  privateCheck('manifest.publication', setup?.manifestPublicationRecorded, 'review_and_publish_signed_manifest');
  privateCheck('application.pairwise_key', setup?.pairwiseKeyConfigured, 'configure_pairwise_key_with_operator');
  const linked = setup?.sources.filter((row) => row.applicationId === setup.applicationId) ?? [];
  const completePage = setup?.nextSourceCursor === null;
  const selected = opts.source ? setup?.sources.find((row) => row.sourceId === opts.source)
    : completePage && linked.length === 1 ? linked[0] : undefined;
  const bound = selected ? selected.applicationId === setup.applicationId
    : setup?.registrationAvailable && !opts.source && completePage && linked.length === 0 ? false : null;
  privateCheck('source.binding', bound, !setup ? 'provide_setup_snapshot' : opts.source && !selected ? 'export_setup_page_containing_source'
    : bound === false ? 'review_and_bind_source_in_console' : 'select_source_from_setup_snapshot');
  const source = bound ? selected : null;
  privateCheck('source.website_dns_recorded', source?.domainVerificationRecorded, 'review_website_dns_challenge');
  privateCheck('source.return_uri', source?.returnRegistered, 'review_and_register_exact_return_uri');
  if (oidc) {
    privateCheck('oidc.exchange_endpoint', setup?.exchangeEndpointActive, 'review_exchange_endpoint_proof');
    privateCheck('oidc.provider_binding', source?.oauthBindingActive, 'review_provider_binding');
    privateCheck('oidc.provider_review', source?.oauthReviewCurrent, 'complete_authorized_provider_review');
    privateCheck('oidc.bootstrap', source?.oauthBootstrapConfirmed, 'complete_browser_bootstrap_and_backend_confirmation');
  }
  return {
    schema: SCHEMA, read_only: true, attester: opts.attester, origin: opts.origin, profile: opts.profile,
    evp_mode: evp ? opts['evp-mode'] : null, capabilities: capabilitiesStatus,
    snapshot: { status: snapshotStatus, observed_at: setup?.observedAt ?? null,
      application_id: setup?.applicationId ?? null, source_id: selected?.sourceId ?? null },
    checks,
    summary: {
      configured: checks.filter((c) => c.status === 'configured').length,
      missing: checks.filter((c) => c.status === 'missing').length,
      unknown: checks.filter((c) => c.status === 'unknown').length,
      human_required: checks.filter((c) => c.human_required).length
    },
    not_checked: ['live_dns', 'sender_domain_authority', 'signing_key_access', 'origin_trial_token',
      'browser_provider_session', 'end_to_end_consent_and_receipt', 'current_permission']
  };
}

export async function fetchCapabilities(origin) {
  const response = await fetch(origin + '/v1/capabilities', {
    method: 'GET', headers: { Accept: 'application/json' }, credentials: 'omit',
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(5000)
  });
  if (response.status !== 200 || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) {
    await response.body?.cancel();
    fail();
  }
  let bytes = 0;
  const chunks = [];
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > LIMIT) fail();
    chunks.push(chunk);
  }
  const data = decode(Buffer.concat(chunks, bytes));
  if (!record(data) || data.protocol !== 'xcim-0.1' || !record(data.identity_evidence) ||
      !Array.isArray(data.identity_evidence.supported_profiles) || !record(data.consent) ||
      typeof data.consent.hosted !== 'boolean') fail();
  return data;
}

export async function run(opts, getCapabilities = fetchCapabilities) {
  let data, caps;
  let snapshotStatus = 'absent', capabilitiesStatus = 'not_checked';
  if (opts.snapshot) {
    try { data = loadSnapshot(opts.snapshot); snapshotStatus = inspectSnapshot(data); }
    catch { snapshotStatus = 'invalid'; }
  }
  if (!opts.offline) {
    try { caps = await getCapabilities(opts.origin); capabilitiesStatus = 'observed'; }
    catch { capabilitiesStatus = 'unavailable'; }
  }
  const report = diagnose(opts, caps, data, snapshotStatus, capabilitiesStatus);
  const code = snapshotStatus === 'invalid' || capabilitiesStatus === 'unavailable' ? 3
    : report.summary.missing || report.summary.unknown ? 2 : 0;
  return { code, report };
}

async function main(argv) {
  const json = argv.includes('--json');
  if (!argv.length || argv.includes('--help') || argv.includes('-h')) {
    console.log(json ? JSON.stringify({ schema: SCHEMA, usage: USAGE }) : USAGE);
    return 0;
  }
  let opts;
  try { opts = parseArgs(argv); } catch {
    if (json) console.log(JSON.stringify({ schema: SCHEMA, error: 'invalid_arguments', usage: USAGE }));
    else console.error(USAGE);
    return 64;
  }
  const { code, report } = await run(opts);
  if (json) console.log(JSON.stringify(report));
  else for (const row of report.checks)
    console.log(row.id + ': ' + row.status + (row.next_action ? ' (' + row.next_action + ')' : ''));
  return code;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
