//! Generator for `policy.schema.json`: the versioned JSON Schema (draft
//! 2020-12) describing the perch [`PolicyDoc`](perch_ir::PolicyDoc) JSON wire
//! surface.
//!
//! # One declaration for the representable limits
//!
//! The schema is a *host-side* projection of the authoritative wire contract
//! in `perch-ir` (`parse.rs` for shape, `validate.rs` for the representable
//! format/range rules) and the per-document caps in `perch-doc-compiler`. Every
//! limit the schema can express is taken from its one declared source —
//! [`perch_ir::MAX_SIGNER_KEY_LEN`] and [`perch_ir::ACK_SENTINEL`] directly, the
//! strkey/hex shapes and the `m <= N` / `quorum <= count` / `limit` rules
//! behaviourally, and the `perch_doc_compiler` caps (`MAX_DOC_SIGNERS`,
//! `MAX_DOC_RULES`, `MAX_RULE_NAME_BYTES`) read straight from the constants — so
//! there is a single place each limit is declared. Two guards keep the
//! projection honest:
//!
//! - the **drift** test regenerates the committed artifact and fails if it
//!   moved (so tightening a perch-ir constant without regenerating is caught);
//! - the **limits-parity** test feeds real inputs through perch-ir's own
//!   `from_json` + `validate` and asserts the schema accepts/rejects exactly at
//!   the boundary where each limit sits (so the schema and the validator cannot
//!   silently disagree — the brief's sanctioned alternative to generating the
//!   numbers straight from the constants).
//!
//! # What this generator is *not* in the build graph of
//!
//! This crate is host-only. It is a dependency of no deployable contract, uses
//! `serde_json` only to assemble JSON off-chain, and never compiles to
//! `wasm32`. It reads `perch-doc-compiler`'s caps with `default-features = false`
//! (so none of that crate's on-chain parser/compiler code is pulled in), and
//! because nothing on a contract's build graph depends on this crate, none of
//! it reaches a wasm build. perch-ir stays serde-free and float-free; nothing
//! here changes that. See `docs/schema.md`.

use serde_json::{json, Value};

/// The schema's stable identity (`$id`). It resolves, once the package is
/// published, to the copy shipped inside the `@stellar-registry/perch` npm
/// package — the documented consumption path (`docs/schema.md`).
pub const SCHEMA_ID: &str = "https://unpkg.com/@stellar-registry/perch/schemas/policy.schema.json";

/// The JSON Schema dialect this generator targets (`$schema`).
pub const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The committed artifact's path, relative to the workspace root. It lives
/// inside the npm package so `npm publish` ships it; the drift test and the
/// `perch-schema-gen` binary both resolve it from here.
pub const CANONICAL_RELPATH: &str = "packages/perch-js/schemas/policy.schema.json";

/// A contract-address strkey (`C…`): 56 chars, base32 alphabet, leading `C`.
/// Mirrors `perch_ir`'s `is_contract_address_shape`; the CRC16 checksum is not
/// a structural property and stays outside the schema (see `docs/schema.md`).
pub const CONTRACT_STRKEY_PATTERN: &str = "^C[A-Z2-7]{55}$";

/// A contract- or account-address strkey (`C…`/`G…`): 56 chars, base32,
/// leading `C` or `G`. Mirrors `perch_ir`'s `is_address_shape`.
pub const ADDRESS_STRKEY_PATTERN: &str = "^[CG][A-Z2-7]{55}$";

/// A SHA-256 digest as 64 lowercase hex characters. Mirrors `perch_ir`'s
/// `is_sha256_hex` (used for `baseline.doc-hash`, `circuit-id`, `enrollment-id`
/// and the structural half of `commitment`).
pub const SHA256_HEX_PATTERN: &str = "^[0-9a-f]{64}$";

/// The hex-string pattern for an external signer's `key`: 1..=`N` whole bytes,
/// where `N` is [`perch_ir::MAX_SIGNER_KEY_LEN`]. Pairs of hex digits enforce
/// the even-length requirement `hex::decode` imposes, and the `{1,N}` bound is
/// the decoded-length window `validate` checks — so the one perch-ir constant
/// drives the schema limit.
///
/// The hex class is deliberately case-INSENSITIVE (`[0-9a-fA-F]`): perch-ir
/// decodes the key with `hex::decode`, which accepts either case and dedupes
/// physical keys on decoded bytes regardless of case (`validate.rs`). Pinning
/// this to lowercase would reject keys the parser accepts — a canonical-form
/// tightening that belongs to CANON v2, not this schema (see `docs/schema.md`).
#[must_use]
pub fn signer_key_pattern() -> String {
    format!("^([0-9a-fA-F]{{2}}){{1,{}}}$", perch_ir::MAX_SIGNER_KEY_LEN)
}

/// Rule names are capped at [`perch_doc_compiler::MAX_RULE_NAME_BYTES`] **bytes**
/// by the compiler (OZ's context-rule name limit). JSON Schema's `maxLength`
/// counts Unicode code points, not bytes, so a multi-byte character would let a
/// code-point count slip past the byte cap. Restricting the name to ASCII makes
/// one character exactly one byte, so `maxLength` then faithfully encodes the
/// byte cap. This is the one place the schema is deliberately *stricter* than
/// the compiler (a non-ASCII name under the byte cap is schema-rejected though
/// the compiler would accept it); JSON Schema cannot express a UTF-8 byte cap
/// directly, and failing closed on exotic names is the safe direction for a
/// review/editing schema. See `docs/schema.md`.
pub const RULE_NAME_PATTERN: &str = "^[\\x00-\\x7F]*$";

/// The `cap.limit` pattern: a POSITIVE decimal integer as a string. perch-ir
/// validates it with `cap.limit.parse::<i128>()` then rejects `v <= 0`, so the
/// parser today accepts an optional leading `+` and leading zeros (an alternate
/// spelling of the same value) and rejects `0`, a sign-minus, and any non-digit.
/// This pattern matches that exactly:
///
/// - `\+?` — optional leading `+` (the parser accepts it; forbidding it is a
///   canonical-form rule deferred to CANON v2, `docs/schema.md`);
/// - `0*` — any run of leading zeros (likewise accepted today, deferred to v2);
/// - `[1-9][0-9]{0,N-1}` — at least one significant non-zero digit, capping the
///   SIGNIFICANT digits at `N` = `i128::MAX`'s decimal width. This rejects `0`
///   and all-zero spellings (positivity, which perch-ir enforces) and any value
///   with more significant digits than `i128::MAX` can hold (which the parser
///   rejects as overflow), while leaving the *exact* `i128` upper bound — a
///   39-digit value above `i128::MAX` — to perch-ir's `parse::<i128>()`.
#[must_use]
pub fn limit_pattern() -> String {
    // The widest a positive i128 gets in decimal (39), computed so the bound is
    // not a magic number.
    let max_digits = i128::MAX.to_string().len();
    format!("^\\+?0*[1-9][0-9]{{0,{}}}$", max_digits - 1)
}

/// The `if`/`then` chain encoding a referenced-count upper bound (`m <= N`,
/// `quorum <= guardian count`) that JSON Schema cannot state as arithmetic.
/// For each list length `len` in `1..=cap`, when the tagged object carries
/// `list_field` with exactly `len` items, the bounded `bound_field` is
/// constrained to `maximum: len`. A valid list never exceeds `cap`
/// (`MAX_DOC_SIGNERS`), so the chain is complete for every document perch-ir
/// accepts; a longer list is already perch-ir-invalid for other reasons and the
/// chain simply adds no bound there. See `docs/schema.md`.
fn count_bound_chain(list_field: &str, bound_field: &str, cap: u32) -> Value {
    let rules: Vec<Value> = (1..=cap)
        .map(|len| {
            json!({
                "if": {
                    "required": [list_field, bound_field],
                    "properties": { list_field: { "minItems": len, "maxItems": len } },
                },
                "then": {
                    "properties": { bound_field: { "maximum": len } },
                },
            })
        })
        .collect();
    Value::Array(rules)
}

/// A `u32` field, with an optional lower bound. `max` is always the `u32`
/// ceiling; `min` is `1` for the fields perch-ir's `validate` refuses at `0`
/// (expiries, periods, thresholds, quorums) and `0` otherwise.
fn u32_field(description: &str, min: u64) -> Value {
    json!({
        "type": "integer",
        "minimum": min,
        "maximum": u64::from(u32::MAX),
        "description": description,
    })
}

fn contract_address(description: &str) -> Value {
    json!({ "type": "string", "pattern": CONTRACT_STRKEY_PATTERN, "description": description })
}

fn address(description: &str) -> Value {
    json!({ "type": "string", "pattern": ADDRESS_STRKEY_PATTERN, "description": description })
}

fn sha256_hex(description: &str) -> Value {
    json!({ "type": "string", "pattern": SHA256_HEX_PATTERN, "description": description })
}

/// Build the complete PolicyDoc JSON Schema as a [`Value`].
#[must_use]
pub fn policy_schema() -> Value {
    json!({
        "$schema": SCHEMA_DIALECT,
        "$id": SCHEMA_ID,
        "title": "Perch Policy Document",
        "description":
            "The reviewable artifact at the center of perch: a smart account's signers, \
             rules, scopes, constraints, and optional recovery enrollment. This schema \
             describes document format `version: 1` as perch-ir's strict parser \
             (`from_json`) accepts it and its validator (`validate`) accepts the \
             representable rules. Schema-valid is NOT the same as authorized or \
             canonically encoded: duplicate raw keys, canonical (RFC 8785) encoding, \
             cross-reference and semantic invariants, aggregate resource bounds, \
             signatures, and authorization are all enforced elsewhere — see \
             `docs/schema.md`.",
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "signers", "rules"],
        "properties": {
            "version": {
                "const": 1,
                "description":
                    "Document format version. The only supported value is 1; perch-ir \
                     rejects anything else before looking at the rest of the document. A \
                     future wire format gets a new document version and a new schema \
                     (versioning policy: `docs/schema.md`).",
            },
            "network": {
                "type": "string",
                "description":
                    "Optional network identifier (a passphrase or short name). Omitted \
                     from the canonical form when absent; an explicit JSON null is \
                     rejected, so leave the key out rather than setting it null.",
            },
            "signers": {
                "type": "array",
                "items": { "$ref": "#/$defs/signerDecl" },
                "maxItems": perch_doc_compiler::MAX_DOC_SIGNERS,
                "description":
                    "Declared signers that rules reference by id. At most \
                     MAX_DOC_SIGNERS (the compiler's per-document signer cap). The \
                     canonical-byte budget is a separate aggregate bound the schema \
                     cannot express — see `docs/schema.md`.",
            },
            "rules": {
                "type": "array",
                "items": { "$ref": "#/$defs/rule" },
                "maxItems": perch_doc_compiler::MAX_DOC_RULES,
                "description":
                    "The policy rules. Order is preserved and significant to the hash. \
                     At most MAX_DOC_RULES (the compiler's per-document rule cap).",
            },
            "recovery": {
                "$ref": "#/$defs/recoveryConfig",
                "description":
                    "Optional account-recovery enrollment (reviewable configuration, \
                     never a recovery attempt). Omitted from the canonical form when \
                     absent, so a document that never enrolls recovery hashes exactly \
                     as before this field existed.",
            },
        },
        "$defs": policy_defs(),
        "examples": [example_doc()],
    })
}

/// The schema serialized deterministically: sorted keys (serde_json's default
/// `Map` is a `BTreeMap`), pretty-printed, with a trailing newline.
#[must_use]
pub fn policy_schema_json() -> String {
    let mut s = serde_json::to_string_pretty(&policy_schema()).expect("policy schema serializes");
    s.push('\n');
    s
}

fn policy_defs() -> Value {
    json!({
        "signerDecl": {
            "description":
                "A declared signer: a document-local id plus how it authenticates. The \
                 method is discriminated by field shape, not a `type` tag — \
                 `verifier`+`key` is an external signer checked by a verifier contract, \
                 `address` is a CAP-0071 delegated address. A mixed or incomplete shape \
                 matches neither and fails closed.",
            "type": "object",
            "oneOf": [
                {
                    "title": "External signer",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "verifier", "key"],
                    "properties": {
                        "id": { "type": "string", "description": "Document-local id rules reference. Uniqueness is a semantic check (outside this schema)." },
                        "verifier": contract_address("Verifier contract (C-address) that checks this signer's signatures."),
                        "key": {
                            "type": "string",
                            "pattern": signer_key_pattern(),
                            "description":
                                "Hex-encoded key material, opaque to perch. Decoded length \
                                 must be 1..=MAX_SIGNER_KEY_LEN bytes (the pattern encodes \
                                 that window and the even-length hex requirement).",
                        },
                    },
                },
                {
                    "title": "Delegated signer",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "address"],
                    "properties": {
                        "id": { "type": "string", "description": "Document-local id rules reference." },
                        "address": address("Delegate address (G… account or C… contract) the host authenticates via CAP-0071."),
                    },
                },
            ],
        },

        "rule": {
            "description":
                "A single policy rule: who (`principals`) may do what (`functions`, \
                 `args`) where (`scope`) until when (`not-after-ledger`), with an \
                 optional cumulative spend `cap`.",
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "scope", "principals"],
            "properties": {
                "name": {
                    "type": "string",
                    "pattern": RULE_NAME_PATTERN,
                    "maxLength": perch_doc_compiler::MAX_RULE_NAME_BYTES,
                    "description":
                        "Human-readable rule name. Capped at MAX_RULE_NAME_BYTES bytes by \
                         the compiler; the ASCII pattern makes one character one byte so \
                         maxLength encodes that byte cap (a non-ASCII name is schema- \
                         rejected — see `docs/schema.md`). Uniqueness across rules is a \
                         semantic check (outside this schema).",
                },
                "scope": { "$ref": "#/$defs/scope" },
                "principals": { "$ref": "#/$defs/principals" },
                "functions": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "minLength": 1 },
                    "description":
                        "Allowlist of function names. Omit the field for `all functions`; \
                         an explicit empty list is rejected as ambiguous, and an explicit \
                         null is rejected (it would silently authorize every function).",
                },
                "args": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "$ref": "#/$defs/argConstraint" },
                    "description":
                        "Constraints on call arguments, keyed by index. Omit for \
                         unconstrained; an explicit empty list or null is rejected. \
                         Argument-index uniqueness is a semantic check (outside this schema).",
                },
                "not-after-ledger": u32_field(
                    "Ledger SEQUENCE (not a Unix timestamp) at or after which the rule stops \
                     authorizing. Must be non-zero; omit for no expiry.",
                    1,
                ),
                "cap": { "$ref": "#/$defs/capConstraint" },
            },
        },

        "scope": {
            "description": "Where a rule applies, tagged by `type`.",
            "type": "object",
            "oneOf": [
                {
                    "title": "Contract scope",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "address"],
                    "properties": {
                        "type": { "const": "contract" },
                        "address": contract_address("The contract (C-address) the rule scopes to."),
                    },
                },
                {
                    "title": "Self-admin scope",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type"],
                    "properties": {
                        "type": { "const": "self-admin" },
                    },
                    "description": "Administrative operations on the smart account itself (signer/rule changes, upgrades).",
                },
            ],
        },

        "principals": {
            "description": "Who a rule authorizes, tagged by `type`.",
            "type": "object",
            // `m <= N` for a threshold rule (its `m` at most its referenced
            // signer count). Only a `threshold` object carries both `signers`
            // and `m`, so the chain fires on no other variant. Enumerated up to
            // MAX_DOC_SIGNERS — a threshold can reference at most that many
            // declared signers, so this is complete for every valid document.
            "allOf": count_bound_chain("signers", "m", perch_doc_compiler::MAX_DOC_SIGNERS),
            "oneOf": [
                {
                    "title": "All (N-of-N)",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "signers"],
                    "properties": {
                        "type": { "const": "all" },
                        "signers": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": true,
                            "items": { "type": "string" },
                            "description": "Declared signer ids, all of which must authorize. That each id is declared is a cross-reference check (outside this schema).",
                        },
                    },
                },
                {
                    "title": "Threshold (M-of-N)",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "signers", "m"],
                    "properties": {
                        "type": { "const": "threshold" },
                        "signers": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": true,
                            "items": { "type": "string" },
                            "description": "Declared signer ids the quorum draws from (the N).",
                        },
                        "m": u32_field(
                            "How many of `signers` must authorize (the M). Must satisfy \
                             1 <= m <= N, where N is this rule's referenced signer count; \
                             the upper bound is encoded by the principals `allOf` if/then \
                             chain (`docs/schema.md`).",
                            1,
                        ),
                    },
                },
                {
                    "title": "Self-authenticating (no signature check)",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "policy", "install-param-hex", "ack"],
                    "properties": {
                        "type": { "const": "self-authenticating" },
                        "policy": contract_address("Policy contract (C-address) that authenticates invocations."),
                        "install-param-hex": {
                            "type": "string",
                            "pattern": "^([0-9a-fA-F]{2})*$",
                            "description": "Hex-encoded install parameter passed to the policy (may be empty).",
                        },
                        "ack": {
                            "const": perch_ir::ACK_SENTINEL,
                            "description":
                                "Acknowledgement that this rule carries no signature check of \
                                 its own. Must equal the sentinel verbatim or validation fails.",
                        },
                    },
                },
            ],
        },

        "argConstraint": {
            "description": "A constraint on one call argument.",
            "type": "object",
            "additionalProperties": false,
            "required": ["index", "pred"],
            "properties": {
                "index": u32_field("Zero-based argument index. Unique within a rule's args (a semantic check).", 0),
                "pred": { "$ref": "#/$defs/argPred" },
            },
        },

        "argPred": {
            "description":
                "A stateless predicate over a single call argument (never a running total \
                 across calls), tagged by `type`.",
            "type": "object",
            "oneOf": [
                {
                    "title": "is-self",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type"],
                    "properties": { "type": { "const": "is-self" } },
                    "description": "The argument must be the smart account's own address.",
                },
                {
                    "title": "address-eq",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "address"],
                    "properties": {
                        "type": { "const": "address-eq" },
                        "address": address("The address (C- or G-address) the argument must equal."),
                    },
                },
                {
                    "title": "string-in",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "values"],
                    "properties": {
                        "type": { "const": "string-in" },
                        "values": {
                            "type": "array",
                            "minItems": 1,
                            "uniqueItems": true,
                            "items": { "type": "string" },
                            "description": "The allowed string values (non-empty, no duplicates).",
                        },
                    },
                },
                {
                    "title": "string-prefix",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "prefix"],
                    "properties": {
                        "type": { "const": "string-prefix" },
                        "prefix": { "type": "string", "description": "The required string prefix." },
                    },
                },
                {
                    "title": "u32-eq",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "value"],
                    "properties": {
                        "type": { "const": "u32-eq" },
                        "value": u32_field("The exact u32 value the argument must equal.", 0),
                    },
                },
            ],
        },

        "capConstraint": {
            "description":
                "A cumulative spend cap over a rolling window. Lowers to OpenZeppelin's \
                 stateful `spending_limit` policy (perch itself is stateless).",
            "type": "object",
            "additionalProperties": false,
            "required": ["limit", "period-ledgers"],
            "properties": {
                "token": contract_address("Token contract (C-address) the cap is denominated in. Defaults to the rule's contract scope when omitted; cap/scope agreement is a cross-reference check (outside this schema)."),
                "limit": {
                    "type": "string",
                    "pattern": limit_pattern(),
                    "description":
                        "Maximum cumulative amount as a decimal string (a string, not a \
                         number, because an i128 amount does not fit a JSON number safely). \
                         Must be a POSITIVE integer: the pattern rejects `0`, all-zero \
                         spellings, a sign-minus, and any value with more significant \
                         digits than an i128 can hold. A leading `+` and leading zeros are \
                         accepted (the parser accepts them; a single canonical spelling is \
                         CANON v2, `docs/schema.md`). Only the EXACT i128 upper bound \
                         remains a semantic check in perch-ir's validator.",
                },
                "period-ledgers": u32_field("Rolling-window length in ledgers. Must be non-zero.", 1),
            },
        },

        "recoveryConfig": {
            "description":
                "Opt-in account-recovery enrollment — who may recover this account and how. \
                 Reviewable configuration only, never the recovery attempt itself (see \
                 `docs/recovery/spec.md`).",
            "type": "object",
            "additionalProperties": false,
            "required": ["profile", "mode", "controller", "replaceable", "delay-ledgers", "expiry-ledgers", "max-cancels"],
            "properties": {
                "profile": {
                    "enum": ["loss", "protected"],
                    "description":
                        "`loss`: the owner may reconfigure/remove recovery and cancel any \
                         attempt alone, keeping activity while an attempt is authorized. \
                         `protected`: reconfiguration/removal/upgrades also need the enrolled \
                         condition, and the account freezes while an attempt is authorized.",
                },
                "mode": { "$ref": "#/$defs/recoveryMode" },
                "controller": contract_address("The adopted recovery controller instance (C-address)."),
                "baseline": {
                    "$ref": "#/$defs/baselineCommitment",
                    "description": "Commitment to the baseline document compromise recovery restores. Omit to restrict the account to lost-key recovery.",
                },
                "replaceable": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string" },
                    "description": "Declared signer ids a recovery attempt may replace (non-empty, no duplicates). That each id is declared is a cross-reference check (outside this schema).",
                },
                "delay-ledgers": u32_field("Ledgers between an attempt becoming authorized and completable. Must be non-zero.", 1),
                "expiry-ledgers": u32_field("Evidence/completion window and the furthest a reconfiguration or upgrade approval may reach. Must be non-zero.", 1),
                "max-cancels": u32_field("Cap on evidence-based cancellations of authorized attempts. Must be non-zero.", 1),
            },
        },

        "recoveryMode": {
            "description":
                "How a recovery attempt is authorized, tagged by `type`. `combined` requires \
                 BOTH a valid proof and a guardian quorum against the same statement.",
            "type": "object",
            // `quorum <= guardian count` for the guardian-bearing modes
            // (`guardian-only`, `combined`); `zk-only` carries neither field so
            // the chain never fires on it. Guardians have no dedicated numeric
            // cap constant (they are bounded only by the canonical-byte budget),
            // so this enumerates to MAX_DOC_SIGNERS as a documented depth; a
            // larger guardian set has `quorum <= count` checked by perch-ir's
            // validator (`docs/schema.md`, deferred to CANON v2).
            "allOf": count_bound_chain("guardians", "quorum", perch_doc_compiler::MAX_DOC_SIGNERS),
            "oneOf": [
                {
                    "title": "guardian-only",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "guardians", "quorum"],
                    "properties": {
                        "type": { "const": "guardian-only" },
                        "guardians": { "$ref": "#/$defs/guardians" },
                        "quorum": { "$ref": "#/$defs/quorum" },
                    },
                },
                {
                    "title": "zk-only",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "adapter", "circuit-id", "pool", "enrollment-id", "commitment"],
                    "properties": {
                        "type": { "const": "zk-only" },
                        "adapter": { "$ref": "#/$defs/zkAdapter" },
                        "circuit-id": { "$ref": "#/$defs/circuitId" },
                        "pool": { "$ref": "#/$defs/zkPool" },
                        "enrollment-id": { "$ref": "#/$defs/enrollmentId" },
                        "commitment": { "$ref": "#/$defs/commitment" },
                    },
                },
                {
                    "title": "combined",
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "guardians", "quorum", "adapter", "circuit-id", "pool", "enrollment-id", "commitment"],
                    "properties": {
                        "type": { "const": "combined" },
                        "guardians": { "$ref": "#/$defs/guardians" },
                        "quorum": { "$ref": "#/$defs/quorum" },
                        "adapter": { "$ref": "#/$defs/zkAdapter" },
                        "circuit-id": { "$ref": "#/$defs/circuitId" },
                        "pool": { "$ref": "#/$defs/zkPool" },
                        "enrollment-id": { "$ref": "#/$defs/enrollmentId" },
                        "commitment": { "$ref": "#/$defs/commitment" },
                    },
                },
            ],
        },

        "guardians": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": true,
            "items": address("A guardian address (C- or G-address)."),
            "description": "The guardian set: independent principals (not document signers). Non-empty, no duplicates.",
        },
        "quorum": u32_field("How many guardians must authorize. Must satisfy 1 <= quorum <= guardian count; the upper bound is encoded by the recoveryMode `allOf` if/then chain, up to MAX_DOC_SIGNERS guardians (`docs/schema.md`).", 1),
        "zkAdapter": contract_address("The ZK adapter the controller calls (C-address)."),
        "zkPool": contract_address("The membership pool whose roots proofs must use (C-address)."),
        "circuitId": sha256_hex("sha256 of the verifier's verification key (64 lowercase hex)."),
        "enrollmentId": sha256_hex("32 random bytes naming the enrolled credential (64 lowercase hex)."),
        "commitment": sha256_hex(
            "The credential's inner commitment (64 lowercase hex). That it encodes a \
             CANONICAL BN254 field element (below the scalar modulus) is a semantic range \
             check enforced by perch-ir's validator, outside this schema.",
        ),
        "baselineCommitment": {
            "type": "object",
            "additionalProperties": false,
            "required": ["doc-hash"],
            "properties": {
                "doc-hash": sha256_hex("Canonical doc_hash (64 lowercase hex) of the baseline document."),
            },
        },
    })
}

/// A minimal, valid example document used in the schema's `examples` (the plain
/// `admin` self-admin rule plus a scoped, expiring CI-publish rule).
fn example_doc() -> Value {
    json!({
        "version": 1,
        "network": "Test SDF Network ; September 2015",
        "signers": [
            {
                "id": "admin",
                "verifier": "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN",
                "key": "045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e"
            }
        ],
        "rules": [
            {
                "name": "admin",
                "scope": { "type": "self-admin" },
                "principals": { "type": "all", "signers": ["admin"] }
            }
        ]
    })
}
