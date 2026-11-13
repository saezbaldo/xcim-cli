#!/usr/bin/env node
import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const LIMIT = 256 * 1024;
const SCHEMA = 'xcim-doctor/v1';
const COMPANY_SNAPSHOT = 'xcim-doctor/company-snapshot/v1';
const ESP_SNAPSHOT = 'xcim-doctor/esp-snapshot/v1';
const OIDC_SCOPE_NOTE = 'Recorded OIDC exchange, binding, review and bootstrap checks describe the Emabled-hosted relay, not site-managed OIDC. The snapshot does not establish which OIDC mode the site uses.';
const SITE_OIDC_NOTE = 'Site-managed OIDC setup is not assessed by Doctor. Independently verify the site backend and the end-to-end identity and consent flow.';
const USAGE = 'xcim doctor [--attester emabled|https://host] [--workflow company|esp] [--profile evp|oidc|both] [--evp-mode vendor|hosted] [--oidc-mode hosted|site-managed] [--intent operate|test] [--snapshot FILE [--source src_ID]] [--offline] [--json]';
const APP = /^urn:xcim:app:[A-Za-z0-9._~-]{1,54}$/;
const SOURCE = /^src_[A-Za-z0-9_-]{4,43}$/;
const REQUEST = /^pr_[A-Za-z0-9_-]{5,44}$/;
const DATE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)$/;
const APP_FIELDS = ['manifestPublicationRecorded', 'exchangeEndpointActive', 'pairwiseKeyConfigured'];
const SOURCE_FIELDS = ['domainVerificationRecorded', 'returnRegistered', 'oauthBindingActive', 'oauthReviewCurrent', 'oauthBootstrapConfirmed'];
const ESP_FIELDS = ['credentialsEnabled', 'listValidationEnabled', 'eligibleRole', 'mfaRequired', 'partnerIdentityActive', 'delegationAvailable'];
const COMPANY_KEYS = ['schema', 'observedAt', 'applicationId', 'requestId', 'requestStatus', 'registrationAvailable',
  'sources', 'nextSourceCursor', ...APP_FIELDS];
const SOURCE_KEYS = ['sourceId', 'applicationId', ...SOURCE_FIELDS];
const REQUEST_STATES = ['pending_review', 'approved', 'provisioning', 'active', 'rejected', 'suspended', 'failed'];
const record = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const matches = (v, re) => typeof v === 'string' && v.trim() === v && re.test(v);
const nullableBooleans = (v, fields) => fields.every((key) => v[key] === null || typeof v[key] === 'boolean');
const exactKeys = (v, fields) => Object.keys(v).length === fields.length && fields.every((key) => Object.hasOwn(v, key));
const state = (v) => v === true ? 'configured' : v === false ? 'missing' : 'unknown';
const fail = () => { throw new Error('invalid input'); };
const decode = (b) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));

export function parseArgs(argv) {
  if (argv[0] !== 'doctor') fail();
  const opts = { attester: 'emabled', profile: 'both', 'evp-mode': 'vendor', 'oidc-mode': 'hosted', workflow: 'company', intent: 'operate' };
  const used = new Set();
  for (let i = 1; i < argv.length; i++) {
    const key = argv[i].slice(2);
    if (!argv[i].startsWith('--') || used.has(key)) fail();
    used.add(key);
    if (['json', 'offline'].includes(key)) opts[key] = true;
    else if (['attester', 'profile', 'evp-mode', 'oidc-mode', 'snapshot', 'source', 'workflow', 'intent'].includes(key)) {
      const value = argv[++i];
      if (!value || value.startsWith('--')) fail();
      opts[key] = value;
    } else fail();
  }
  if (!['evp', 'oidc', 'both'].includes(opts.profile) || !['vendor', 'hosted'].includes(opts['evp-mode'])) fail();
  if (!['hosted', 'site-managed'].includes(opts['oidc-mode'])) fail();
  if (!['company', 'esp'].includes(opts.workflow) || !['operate', 'test'].includes(opts.intent)) fail();
  if (opts.intent === 'test' && (opts.workflow !== 'company' || opts.profile === 'evp')) fail();
  if (used.has('oidc-mode') && (opts.workflow !== 'company' || opts.profile === 'evp')) fail();
  if (opts.workflow === 'esp' && ['profile', 'evp-mode', 'source'].some((key) => used.has(key))) fail();
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
    if ((opts.snapshot || opts.workflow === 'esp') && opts.attester === 'custom') fail();
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

function freshness(observedAt, now) {
  if (!matches(observedAt, DATE)) return 'invalid';
  const [year, month, day, hour, minute, second] = observedAt.slice(0, 19).split(/[-T:]/).map(Number);
  const offset = /[+-](\d{2}):(\d{2})$/.exec(observedAt);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  if (!year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day ||
      hour > 23 || minute > 59 || second > 59 || (offset && (+offset[1] > 23 || +offset[2] > 59))) return 'invalid';
  const time = Date.parse(observedAt);
  if (!Number.isFinite(time) || time > now + 300000) return 'invalid';
  return now - time > 86400000 ? 'stale' : 'fresh';
}

export function inspectSnapshot(data, now = Date.now(), workflow = 'company') {
  if (!record(data)) return 'invalid';
  if (workflow === 'esp') {
    if (data.schema !== ESP_SNAPSHOT || !exactKeys(data, ['schema', 'observedAt', ...ESP_FIELDS]) ||
        !nullableBooleans(data, ESP_FIELDS)) return 'invalid';
    return freshness(data.observedAt, now);
  }
  const versioned = Object.hasOwn(data, 'schema');
  const hasSelection = versioned && Object.hasOwn(data, 'selectedSourceId');
  if (versioned && (data.schema !== COMPANY_SNAPSHOT ||
      !exactKeys(data, hasSelection ? [...COMPANY_KEYS, 'selectedSourceId'] : COMPANY_KEYS))) return 'invalid';
  if (!matches(data.applicationId, APP) || !matches(data.requestId, REQUEST) ||
      !REQUEST_STATES.includes(data.requestStatus) || typeof data.registrationAvailable !== 'boolean' ||
      (data.registrationAvailable && data.requestStatus !== 'active') ||
      !nullableBooleans(data, APP_FIELDS) ||
      !Array.isArray(data.sources) || data.sources.length > 25 ||
      (data.nextSourceCursor !== null && !matches(data.nextSourceCursor, SOURCE))) return 'invalid';
  const ids = new Set();
  for (const row of data.sources) {
    if (!record(row) || !matches(row.sourceId, SOURCE) || ids.has(row.sourceId) ||
        (row.applicationId !== null && !matches(row.applicationId, APP)) ||
        !nullableBooleans(row, SOURCE_FIELDS)) return 'invalid';
    if (versioned) {
      const exchange = Object.hasOwn(row, 'exchangeEndpointVerified');
      if (!exactKeys(row, exchange ? [...SOURCE_KEYS, 'exchangeEndpointVerified'] : SOURCE_KEYS) ||
          (exchange && !nullableBooleans(row, ['exchangeEndpointVerified']))) return 'invalid';
    }
    ids.add(row.sourceId);
  }
  if (hasSelection && data.selectedSourceId !== null && !ids.has(data.selectedSourceId)) return 'invalid';
  return freshness(data.observedAt, now);
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
  const add = (id, status, evidence, next_action, actor = 'agent', advisory = false) => {
    const unresolved = status !== 'configured';
    const blocking = unresolved && !advisory;
    checks.push({ id, status, evidence, human_required: blocking && actor !== 'agent',
      next_action: unresolved ? next_action : null, actor: unresolved ? actor : null,
      severity: !unresolved ? 'ok' : advisory ? 'advisory' : 'blocker', blocking });
  };
  const publicCheck = (id, value, action) => add(id, state(value), 'attester_capabilities', action);
  const privateCheck = (id, value, action, actor = 'workspace_admin', advisory = false) => {
    if (value == null && id !== 'setup.snapshot' && id !== 'source.binding') {
      add(id, 'unknown', 'console_snapshot', snapshotStatus === 'fresh'
        ? 'inspect_setup_prerequisites' : 'provide_setup_snapshot');
      return;
    }
    const human = value === false || id === 'setup.snapshot' || action === 'export_setup_page_containing_source';
    add(id, state(value), 'console_snapshot', action, human ? actor : 'agent', advisory);
  };
  const setup = snapshotStatus === 'fresh' ? data : null;
  const finish = (workflow, intent, profile, evpMode, selected, notChecked, notes = []) => ({
    schema: SCHEMA, read_only: true, attester: opts.attester, origin: opts.origin, profile, evp_mode: evpMode,
    workflow, intent, capabilities: capabilitiesStatus,
    snapshot: { status: snapshotStatus, observed_at: setup?.observedAt ?? null,
      application_id: setup?.applicationId ?? null, source_id: selected?.sourceId ?? null },
    checks,
    summary: {
      configured: checks.filter((c) => c.status === 'configured').length,
      missing: checks.filter((c) => c.status === 'missing').length,
      unknown: checks.filter((c) => c.status === 'unknown').length,
      human_required: checks.filter((c) => c.human_required).length,
      blocking: checks.filter((c) => c.blocking).length,
      advisory: checks.filter((c) => c.severity === 'advisory').length
    },
    not_checked: notChecked, notes
  });
  if (opts.workflow === 'esp') {
    privateCheck('setup.snapshot', setup ? true : null, 'export_esp_diagnostics_in_console');
    privateCheck('esp.credentials', setup?.credentialsEnabled, 'check_esp_availability_with_attester', 'attester_operator');
    privateCheck('esp.list_validation', setup?.listValidationEnabled, 'check_list_validation_availability_with_attester', 'attester_operator');
    privateCheck('esp.workspace_role', setup?.eligibleRole, 'ask_workspace_owner_for_eligible_role');
    privateCheck('esp.mfa', setup?.mfaRequired == null ? null : !setup.mfaRequired, 'complete_workspace_mfa', 'browser_user');
    privateCheck('esp.partner_identity', setup?.partnerIdentityActive, 'create_or_review_esp_identity_in_console');
    privateCheck('esp.delegation', setup?.delegationAvailable, 'ask_company_to_authorize_esp_scope', 'company_admin');
    return finish('esp', null, null, null, null,
      ['live_esp_authority', 'list_format', 'recipient_receipts', 'current_permission', 'public_proof', 'deliverability']);
  }
  const evp = opts.profile !== 'oidc';
  const oidc = opts.profile !== 'evp';
  publicCheck('consent.hosted', caps?.consent?.hosted, 'check_attester_capabilities');
  if (evp) publicCheck('evp.delivery_mode', capabilityState(caps, 'evp', opts['evp-mode']), 'choose_supported_evp_mode');
  if (oidc) publicCheck('oidc.support', capabilityState(caps, 'oidc'), 'check_oidc_availability');
  privateCheck('setup.snapshot', setup ? true : null, 'export_current_setup_in_console');
  const requestActions = { pending_review: 'approve_request_in_workspace', approved: 'await_operator_provisioning',
    provisioning: 'await_operator_provisioning', rejected: 'review_rejected_request',
    suspended: 'review_suspended_application', failed: 'review_provisioning_failure' };
  privateCheck('application.registration', setup?.registrationAvailable,
    requestActions[setup?.requestStatus] ?? 'check_application_registration',
    ['approved', 'provisioning', 'failed'].includes(setup?.requestStatus) ? 'attester_operator' : 'workspace_admin');
  privateCheck('manifest.publication', setup?.manifestPublicationRecorded, 'review_and_publish_signed_manifest');
  privateCheck('application.pairwise_key', setup?.pairwiseKeyConfigured, 'configure_pairwise_key_with_operator', 'attester_operator');
  const requestedSource = opts.source ?? (setup?.schema === COMPANY_SNAPSHOT ? setup.selectedSourceId : undefined);
  const linked = setup?.sources.filter((row) => row.applicationId === setup.applicationId) ?? [];
  const completePage = setup?.schema !== COMPANY_SNAPSHOT && setup?.nextSourceCursor === null;
  const selected = requestedSource ? setup?.sources.find((row) => row.sourceId === requestedSource)
    : completePage && linked.length === 1 ? linked[0] : undefined;
  const bound = selected ? selected.applicationId === setup.applicationId
    : setup?.registrationAvailable && !requestedSource && completePage && linked.length === 0 ? false : null;
  privateCheck('source.binding', bound, !setup ? 'provide_setup_snapshot' : opts.source && !selected ? 'export_setup_page_containing_source'
    : bound === false ? 'review_and_bind_source_in_console' : 'select_source_from_setup_snapshot');
  const source = bound ? selected : null;
  privateCheck('source.website_dns_recorded', source?.domainVerificationRecorded, 'review_website_dns_challenge');
  privateCheck('source.return_uri', source?.returnRegistered, 'review_and_register_exact_return_uri');
  if (oidc && opts['oidc-mode'] === 'site-managed') {
    add('oidc.site_managed_setup', 'unknown', 'not_checked', 'verify_site_managed_oidc_setup');
  } else if (oidc) {
    privateCheck('oidc.exchange_endpoint', setup?.schema === COMPANY_SNAPSHOT
      ? source?.exchangeEndpointVerified : setup?.exchangeEndpointActive, 'review_exchange_endpoint_proof');
    privateCheck('oidc.provider_binding', source?.oauthBindingActive, 'review_provider_binding');
    const reviewAdvisory = opts.intent !== 'test' && source?.oauthBindingActive === true &&
      source?.oauthBootstrapConfirmed === true && source?.oauthReviewCurrent === false;
    privateCheck('oidc.provider_review', source?.oauthReviewCurrent,
      reviewAdvisory ? 'review_before_new_oidc_test' : 'complete_authorized_provider_review', 'attester_operator', reviewAdvisory);
    privateCheck('oidc.bootstrap', source?.oauthBootstrapConfirmed, 'complete_browser_bootstrap_and_backend_confirmation', 'browser_user');
  }
  return finish('company', opts.intent ?? 'operate', opts.profile, evp ? opts['evp-mode'] : null, selected,
    ['live_dns', 'sender_domain_authority', 'signing_key_access', 'origin_trial_token',
      'browser_provider_session', 'end_to_end_consent_and_receipt', 'current_permission',
      ...(oidc ? ['site_managed_oidc_setup'] : [])], oidc ? [opts['oidc-mode'] === 'site-managed' ? SITE_OIDC_NOTE : OIDC_SCOPE_NOTE] : []);
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
    try { data = loadSnapshot(opts.snapshot); snapshotStatus = inspectSnapshot(data, Date.now(), opts.workflow); }
    catch { snapshotStatus = 'invalid'; }
  }
  if (!opts.offline && opts.workflow !== 'esp') {
    try { caps = await getCapabilities(opts.origin); capabilitiesStatus = 'observed'; }
    catch { capabilitiesStatus = 'unavailable'; }
  }
  const report = diagnose(opts, caps, data, snapshotStatus, capabilitiesStatus);
  const code = snapshotStatus === 'invalid' || capabilitiesStatus === 'unavailable' ? 3
    : report.summary.blocking ? 2 : 0;
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
  else {
    for (const row of report.checks)
      console.log(row.id + ': ' + row.status + (row.severity === 'advisory' ? ' [advisory]' : '') +
        (row.next_action ? ' (' + row.next_action + ')' : ''));
    for (const note of report.notes) console.log('Note: ' + note);
  }
  return code;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
