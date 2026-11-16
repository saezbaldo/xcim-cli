# Changelog

## 0.3.0

- Distinguish explicitly selected site-managed OIDC from the default hosted relay; report the site-managed setup as unverified rather than requiring relay setup.

## 0.2.0

- Added `--workflow esp` for offline, read-only ESP setup diagnostics. The snapshot contains status flags, not recipient or authorization records.
- Added versioned company snapshots with selected-site and site-specific hosted exchange diagnostics alongside legacy console exports.
- Added OIDC test intent. Expired administrative review remains visible but does not block the default operational diagnosis of an active, confirmed connection.
- Kept `xcim-doctor/v1` and existing status values. Added `actor`, `severity`, and `blocking` to checks; exit `2` now means at least one blocking check.
