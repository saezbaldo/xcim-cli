"""Read-only XCIM integration diagnostics. No runtime dependencies."""
import datetime
import http.client
import json
import os
import queue
import re
import stat
import sys
import threading
import time

LIMIT = 256 * 1024
SCHEMA = "xcim-doctor/v1"
COMPANY_SNAPSHOT = "xcim-doctor/company-snapshot/v1"
ESP_SNAPSHOT = "xcim-doctor/esp-snapshot/v1"
OIDC_SCOPE_NOTE = ("Recorded OIDC exchange, binding, review and bootstrap checks describe the Emabled-hosted relay, "
                   "not site-managed OIDC. The snapshot does not establish which OIDC mode the site uses.")
USAGE = "xcim doctor [--attester emabled|https://host] [--workflow company|esp] [--profile evp|oidc|both] [--evp-mode vendor|hosted] [--intent operate|test] [--snapshot FILE [--source src_ID]] [--offline] [--json]"
APP = r"urn:xcim:app:[A-Za-z0-9._~-]{1,54}"
SOURCE = r"src_[A-Za-z0-9_-]{4,43}"
REQUEST = r"pr_[A-Za-z0-9_-]{5,44}"
DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
APP_FIELDS = ("manifestPublicationRecorded", "exchangeEndpointActive", "pairwiseKeyConfigured")
SOURCE_FIELDS = ("domainVerificationRecorded", "returnRegistered", "oauthBindingActive", "oauthReviewCurrent", "oauthBootstrapConfirmed")
ESP_FIELDS = ("credentialsEnabled", "listValidationEnabled", "eligibleRole", "mfaRequired", "partnerIdentityActive", "delegationAvailable")
COMPANY_KEYS = {"schema", "observedAt", "applicationId", "requestId", "requestStatus", "registrationAvailable",
                "sources", "nextSourceCursor", *APP_FIELDS}
SOURCE_KEYS = {"sourceId", "applicationId", *SOURCE_FIELDS}
ESP_KEYS = {"schema", "observedAt", *ESP_FIELDS}
REQUEST_STATES = ("pending_review", "approved", "provisioning", "active", "rejected", "suspended", "failed")


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def fail():
    raise ValueError("invalid input")


def parse_args(argv):
    if not argv or argv[0] != "doctor":
        fail()
    opts = {"attester": "emabled", "profile": "both", "evp-mode": "vendor", "workflow": "company", "intent": "operate"}
    used = set()
    values = iter(argv[1:])
    for arg in values:
        key = arg[2:]
        if not arg.startswith("--") or key in used:
            fail()
        used.add(key)
        if key in ("json", "offline"):
            opts[key] = True
        elif key in ("attester", "profile", "evp-mode", "snapshot", "source", "workflow", "intent"):
            value = next(values, None)
            if not value or value.startswith("--"):
                fail()
            opts[key] = value
        else:
            fail()
    if opts["profile"] not in ("evp", "oidc", "both") or opts["evp-mode"] not in ("vendor", "hosted"):
        fail()
    if opts["workflow"] not in ("company", "esp") or opts["intent"] not in ("operate", "test"):
        fail()
    if opts["intent"] == "test" and (opts["workflow"] != "company" or opts["profile"] == "evp"):
        fail()
    if opts["workflow"] == "esp" and used.intersection(("profile", "evp-mode", "source")):
        fail()
    if "source" in opts and ("snapshot" not in opts or not matches(opts["source"], SOURCE)):
        fail()
    if opts["attester"] == "emabled":
        opts["origin"] = "https://api.emabled.com"
    else:
        match = re.fullmatch(r"https://([a-z0-9.-]+)/?", opts["attester"], re.I | re.ASCII)
        labels = match[1].lower().split(".") if match else []
        if (not match or len(labels) < 2 or len(match[1]) > 253 or not re.match("[a-z]", labels[-1])
                or any(not matches(label, r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?") for label in labels)):
            fail()
        opts["origin"] = "https://" + ".".join(labels)
        opts["attester"] = "emabled" if opts["origin"] == "https://api.emabled.com" else "custom"
        if ("snapshot" in opts or opts["workflow"] == "esp") and opts["attester"] == "custom":
            fail()
    return opts


def decode(data):
    return json.loads(data.decode("utf-8-sig"), parse_constant=lambda _: fail())


def load_snapshot(path):
    if re.match(r"^(?:[\\/]{2}|[a-z]+://)", path, re.I) or not stat.S_ISREG(os.lstat(path).st_mode):
        fail()
    with open(path, "rb") as file:
        metadata = os.fstat(file.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > LIMIT:
            fail()
        data = file.read(LIMIT + 1)
    if len(data) > LIMIT:
        fail()
    return decode(data)


def nullable_booleans(value, fields):
    return all(key in value and (value[key] is None or type(value[key]) is bool) for key in fields)


def freshness(observed_at, now):
    now = time.time_ns() // 1_000_000 / 1000 if now is None else now
    if not matches(observed_at, DATE):
        return "invalid"
    offset = re.search(r"[+-]([0-9]{2}):([0-9]{2})$", observed_at)
    if offset and (int(offset[1]) > 23 or int(offset[2]) > 59):
        return "invalid"
    date = re.sub(r"\.(\d{1,7})", lambda m: "." + (m[1] + "000")[:3], observed_at)
    try:
        observed = datetime.datetime.fromisoformat(date.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError, OSError):
        return "invalid"
    if observed > now + 300:
        return "invalid"
    return "stale" if now - observed > 86400 else "fresh"


def inspect_snapshot(data, now=None, workflow="company"):
    if not isinstance(data, dict):
        return "invalid"
    if workflow == "esp":
        if data.get("schema") != ESP_SNAPSHOT or data.keys() != ESP_KEYS or not nullable_booleans(data, ESP_FIELDS):
            return "invalid"
        return freshness(data["observedAt"], now)
    versioned = "schema" in data
    has_selection = versioned and "selectedSourceId" in data
    if versioned and (data["schema"] != COMPANY_SNAPSHOT
                      or data.keys() != (COMPANY_KEYS | {"selectedSourceId"} if has_selection else COMPANY_KEYS)):
        return "invalid"
    if (not matches(data.get("applicationId"), APP)
            or not matches(data.get("requestId"), REQUEST) or data.get("requestStatus") not in REQUEST_STATES
            or type(data.get("registrationAvailable")) is not bool
            or (data["registrationAvailable"] and data["requestStatus"] != "active")
            or not nullable_booleans(data, APP_FIELDS)
            or not isinstance(data.get("sources"), list) or len(data["sources"]) > 25
            or "nextSourceCursor" not in data
            or (data["nextSourceCursor"] is not None and not matches(data["nextSourceCursor"], SOURCE))):
        return "invalid"
    ids = set()
    for row in data["sources"]:
        if (not isinstance(row, dict) or not matches(row.get("sourceId"), SOURCE)
                or row["sourceId"] in ids or "applicationId" not in row
                or (row["applicationId"] is not None and not matches(row["applicationId"], APP))
                or not nullable_booleans(row, SOURCE_FIELDS)):
            return "invalid"
        if versioned:
            exchange = "exchangeEndpointVerified" in row
            if (row.keys() != (SOURCE_KEYS | {"exchangeEndpointVerified"} if exchange else SOURCE_KEYS)
                    or (exchange and not nullable_booleans(row, ("exchangeEndpointVerified",)))):
                return "invalid"
        ids.add(row["sourceId"])
    if has_selection and data["selectedSourceId"] is not None and (
            not matches(data["selectedSourceId"], SOURCE) or data["selectedSourceId"] not in ids):
        return "invalid"
    return freshness(data.get("observedAt"), now)


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


def capability_state(caps, profile, mode):
    if not caps:
        return None
    identity = caps["identity_evidence"]
    if profile == "oidc":
        status = object_or_empty(identity.get("oidc_01")).get("status")
    else:
        modes = object_or_empty(object_or_empty(identity.get("evp_01")).get("delivery_modes"))
        status = object_or_empty(modes.get("vendor_origin_handoff" if mode == "vendor" else "emabled_hosted")).get("status")
    if status == "unavailable":
        return False
    if status in ("supported", "experimental") and profile + "-01" in identity["supported_profiles"]:
        return True
    return None


def diagnose(opts, caps, data, snapshot_status, capabilities_status):
    checks = []

    def add(id_, value, evidence, action, actor="agent", advisory=False):
        status = "configured" if value is True else "missing" if value is False else "unknown"
        unresolved = status != "configured"
        blocking = unresolved and not advisory
        checks.append({"id": id_, "status": status, "evidence": evidence,
                       "human_required": blocking and actor != "agent", "next_action": action if unresolved else None,
                       "actor": actor if unresolved else None,
                       "severity": "ok" if not unresolved else "advisory" if advisory else "blocker", "blocking": blocking})

    def public_check(id_, value, action):
        add(id_, value, "attester_capabilities", action)

    def private_check(id_, value, action, actor="workspace_admin", advisory=False):
        if value is None and id_ not in ("setup.snapshot", "source.binding"):
            add(id_, None, "console_snapshot",
                "inspect_setup_prerequisites" if snapshot_status == "fresh" else "provide_setup_snapshot")
            return
        human = value is False or id_ == "setup.snapshot" or action == "export_setup_page_containing_source"
        add(id_, value, "console_snapshot", action, actor if human else "agent", advisory)

    setup = data if snapshot_status == "fresh" else {}

    def finish(workflow, intent, profile, evp_mode, selected, not_checked, notes=()):
        return {
            "schema": SCHEMA, "read_only": True, "attester": opts["attester"], "origin": opts["origin"],
            "profile": profile, "evp_mode": evp_mode, "workflow": workflow, "intent": intent,
            "capabilities": capabilities_status,
            "snapshot": {"status": snapshot_status, "observed_at": setup.get("observedAt"),
                         "application_id": setup.get("applicationId"), "source_id": selected.get("sourceId")},
            "checks": checks,
            "summary": {**{s: sum(row["status"] == s for row in checks) for s in ("configured", "missing", "unknown")},
                        "human_required": sum(row["human_required"] for row in checks),
                        "blocking": sum(row["blocking"] for row in checks),
                        "advisory": sum(row["severity"] == "advisory" for row in checks)},
            "not_checked": not_checked, "notes": list(notes),
        }

    if opts.get("workflow") == "esp":
        private_check("setup.snapshot", True if setup else None, "export_esp_diagnostics_in_console")
        private_check("esp.credentials", setup.get("credentialsEnabled"), "check_esp_availability_with_attester", "attester_operator")
        private_check("esp.list_validation", setup.get("listValidationEnabled"),
                      "check_list_validation_availability_with_attester", "attester_operator")
        private_check("esp.workspace_role", setup.get("eligibleRole"), "ask_workspace_owner_for_eligible_role")
        private_check("esp.mfa", None if setup.get("mfaRequired") is None else not setup["mfaRequired"],
                      "complete_workspace_mfa", "browser_user")
        private_check("esp.partner_identity", setup.get("partnerIdentityActive"), "create_or_review_esp_identity_in_console")
        private_check("esp.delegation", setup.get("delegationAvailable"), "ask_company_to_authorize_esp_scope", "company_admin")
        return finish("esp", None, None, None, {},
                      ["live_esp_authority", "list_format", "recipient_receipts", "current_permission", "public_proof", "deliverability"])

    evp, oidc = opts["profile"] != "oidc", opts["profile"] != "evp"
    public_check("consent.hosted", caps["consent"]["hosted"] if caps else None, "check_attester_capabilities")
    if evp:
        public_check("evp.delivery_mode", capability_state(caps, "evp", opts["evp-mode"]), "choose_supported_evp_mode")
    if oidc:
        public_check("oidc.support", capability_state(caps, "oidc", None), "check_oidc_availability")
    private_check("setup.snapshot", True if setup else None, "export_current_setup_in_console")
    actions = {"pending_review": "approve_request_in_workspace", "approved": "await_operator_provisioning",
               "provisioning": "await_operator_provisioning", "rejected": "review_rejected_request",
               "suspended": "review_suspended_application", "failed": "review_provisioning_failure"}
    private_check("application.registration", setup.get("registrationAvailable"),
                  actions.get(setup.get("requestStatus"), "check_application_registration"),
                  "attester_operator" if setup.get("requestStatus") in ("approved", "provisioning", "failed") else "workspace_admin")
    private_check("manifest.publication", setup.get("manifestPublicationRecorded"), "review_and_publish_signed_manifest")
    private_check("application.pairwise_key", setup.get("pairwiseKeyConfigured"), "configure_pairwise_key_with_operator", "attester_operator")
    versioned = setup.get("schema") == COMPANY_SNAPSHOT
    requested_source = opts.get("source", setup.get("selectedSourceId") if versioned else None)
    linked = [row for row in setup.get("sources", []) if row["applicationId"] == setup["applicationId"]]
    complete_page = bool(setup) and not versioned and setup["nextSourceCursor"] is None
    selected = (next((row for row in setup.get("sources", []) if row["sourceId"] == requested_source), {})
                if requested_source else linked[0] if complete_page and len(linked) == 1 else {})
    bound = (selected["applicationId"] == setup["applicationId"] if selected
             else False if setup.get("registrationAvailable") and not requested_source and complete_page and not linked else None)
    private_check("source.binding", bound, "provide_setup_snapshot" if not setup
                  else "export_setup_page_containing_source" if "source" in opts and not selected
                  else "review_and_bind_source_in_console" if bound is False else "select_source_from_setup_snapshot")
    source = selected if bound else {}
    private_check("source.website_dns_recorded", source.get("domainVerificationRecorded"), "review_website_dns_challenge")
    private_check("source.return_uri", source.get("returnRegistered"), "review_and_register_exact_return_uri")
    if oidc:
        exchange = source.get("exchangeEndpointVerified") if versioned else setup.get("exchangeEndpointActive")
        private_check("oidc.exchange_endpoint", exchange, "review_exchange_endpoint_proof")
        private_check("oidc.provider_binding", source.get("oauthBindingActive"), "review_provider_binding")
        review_advisory = (opts.get("intent") != "test" and source.get("oauthBindingActive") is True
                           and source.get("oauthBootstrapConfirmed") is True and source.get("oauthReviewCurrent") is False)
        private_check("oidc.provider_review", source.get("oauthReviewCurrent"),
                      "review_before_new_oidc_test" if review_advisory else "complete_authorized_provider_review",
                      "attester_operator", review_advisory)
        private_check("oidc.bootstrap", source.get("oauthBootstrapConfirmed"),
                      "complete_browser_bootstrap_and_backend_confirmation", "browser_user")
    return finish("company", opts.get("intent", "operate"), opts["profile"], opts["evp-mode"] if evp else None, selected,
                  ["live_dns", "sender_domain_authority", "signing_key_access", "origin_trial_token",
                   "browser_provider_session", "end_to_end_consent_and_receipt", "current_permission"]
                  + (["site_managed_oidc_setup"] if oidc else []), [OIDC_SCOPE_NOTE] if oidc else [])


def fetch_capabilities(origin):
    def request():
        with_connection = http.client.HTTPSConnection(origin.removeprefix("https://"), timeout=5)
        try:
            with_connection.request("GET", "/v1/capabilities", headers={"Accept": "application/json"})
            response = with_connection.getresponse()
            if response.status != 200 or not re.match(r"application/json(?:;|$)", response.getheader("Content-Type", ""), re.I):
                fail()
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                fail()
            payload = decode(data)
            if (not isinstance(payload, dict) or payload.get("protocol") != "xcim-0.1"
                    or not isinstance(object_or_empty(payload.get("identity_evidence")).get("supported_profiles"), list)
                    or type(object_or_empty(payload.get("consent")).get("hosted")) is not bool):
                fail()
            return payload
        finally:
            with_connection.close()

    result = queue.Queue(maxsize=1)

    def bounded_request():
        try:
            result.put(request())
        except Exception:
            result.put(None)

    threading.Thread(target=bounded_request, daemon=True).start()
    payload = result.get(timeout=5)
    if payload is None:
        fail()
    return payload


def run(opts, get_capabilities=fetch_capabilities):
    data = caps = None
    snapshot_status, capabilities_status = "absent", "not_checked"
    if opts.get("snapshot"):
        try:
            data = load_snapshot(opts["snapshot"])
            snapshot_status = inspect_snapshot(data, workflow=opts.get("workflow", "company"))
        except (OSError, ValueError, RecursionError):
            snapshot_status = "invalid"
    if not opts.get("offline") and opts.get("workflow") != "esp":
        try:
            caps = get_capabilities(opts["origin"])
            capabilities_status = "observed"
        except (OSError, ValueError, queue.Empty, http.client.HTTPException):
            capabilities_status = "unavailable"
    report = diagnose(opts, caps, data, snapshot_status, capabilities_status)
    code = (3 if snapshot_status == "invalid" or capabilities_status == "unavailable"
            else 2 if report["summary"]["blocking"] else 0)
    return code, report


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    json_mode = "--json" in argv
    if not argv or "--help" in argv or "-h" in argv:
        print(json.dumps({"schema": SCHEMA, "usage": USAGE}) if json_mode else USAGE)
        return 0
    try:
        opts = parse_args(argv)
    except ValueError:
        if json_mode:
            print(json.dumps({"schema": SCHEMA, "error": "invalid_arguments", "usage": USAGE}))
        else:
            print(USAGE, file=sys.stderr)
        return 64
    code, report = run(opts)
    if json_mode:
        print(json.dumps(report, separators=(",", ":")))
    else:
        for row in report["checks"]:
            action = " (" + row["next_action"] + ")" if row["next_action"] else ""
            advisory = " [advisory]" if row["severity"] == "advisory" else ""
            print(row["id"] + ": " + row["status"] + advisory + action)
        for note in report["notes"]:
            print("Note: " + note)
    return code


if __name__ == "__main__":
    sys.exit(main())
