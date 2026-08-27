# Perch Web policy profile

`perch-web/v1` is independent of Perch PolicyDoc v1 and CANON v1. It targets
WebMCP tools exposed through named WIT arguments.

The document binds one HTTPS origin, one WIT package or component identity,
one manifest SHA-256 hash, one principal, and one UTC expiry. Each grant binds
one tool export, every named argument constraint, allowed effects, an approval
requirement, and a revocation identity.

A tool export uses `namespace:package[@major.minor.patch]/interface#function`.
Each name starts with a lowercase letter. Each name then uses lowercase letters,
digits, or hyphens. The version is optional and contains three decimal parts.

The origin uses its canonical HTTPS origin form. It has no credentials, path,
query, fragment, wildcard, or trailing slash. An expiry uses the exact
`YYYY-MM-DDTHH:MM:SSZ` UTC whole-second form and occurs after the Unix epoch.

The supported argument predicates are `string-eq`, `string-in`, `bool-eq`, and
`u64-eq`. A WIT `u64` uses a canonical unsigned decimal string. The supported
effects are `dom-read`, `dom-write`, `network-request`, `user-download`, and
`persistent-storage`.

The compiler produces a BrowserPlan and a ServerPlan. Both plans contain the
same policy hash and policy data. Only the plan format name differs. The plans
contain data only. The compiler does not generate executable policy code.

A host must obtain the origin, package or component identity, manifest hash,
principal, current time, effects, approval result, and revoked identities from
trusted sources. The host must convert the WIT call to an exact map of named
arguments. The checker denies missing arguments and additional arguments.
Web profile v1 rejects an empty constraint list. It cannot authorize a tool
that has no WIT arguments.

The host must check the BrowserPlan before browser execution. The server must
independently check the ServerPlan before tool execution. A Site Rescue adapter
can load [`testdata/web/site-rescue.policy.json`](testdata/web/site-rescue.policy.json),
compile it once, and distribute the two plan values to these enforcement points.

## Web canonical form v1

The canonical bytes use UTF-8 JSON without whitespace. Object keys sort by raw
UTF-16 code units. Array order stays unchanged. Strings use JSON escapes with
lowercase hexadecimal control escapes. The typed model contains no floating
point numbers. The policy hash is lowercase hexadecimal SHA-256 of these bytes.

The profile string is part of the hash input. Any incompatible canonical change
requires a new Web profile and canonical version. It does not change CANON v1.

The policy hash is `SHA-256(canonical_bytes(document))`. The canonical version
constant `WEB_CANON_VERSION` is a format identifier. The constant is not part
of the preimage. The Site Rescue vector hash is
`874cf21112f5067d939b951570f6d7554db8b3f32e0d1e4c8c491bac1532f138`.

A grant ID uses 1 to 128 non-control UTF-8 bytes. A revocation ID uses 1 to 256
non-control UTF-8 bytes. These values are opaque case-sensitive identities.
The manifest hash uses 64 lowercase hexadecimal characters.

The BrowserPlan supports browser approval and display behavior. The ServerPlan
is the final authorization gate. The BrowserPlan is advisory and does not
replace the ServerPlan check. Both plans contain the same policy data.

This first target does not define a revocation service or WIT manifest loader.
It does not define cumulative limits or rate limits. The integrating host
supplies the external inputs. The implementation has not received a security
audit.
