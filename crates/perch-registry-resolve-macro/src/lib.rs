//! Proc-macro backing [`perch_registry_resolve::registry_contract`].
//!
//! Do not depend on this crate directly — use `perch-registry-resolve`, which
//! re-exports the macro and carries the docs + tests. This crate exists only
//! because a `proc-macro = true` crate cannot also export the library items and
//! `Env`-driven tests that exercise the generated code.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    ext::IdentExt,
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, LitStr, Path, Token,
};

/// See the crate-level docs of `perch-registry-resolve` for the full grammar.
///
/// ```ignore
/// // Name-only (positional), like `import_contract_client!`:
/// registry_contract!(perch_interpreter);   // wasm "perch-interpreter", pin = sha256(wasm/…)
///
/// // Keyed, e.g. a compile-time-pinned hash literal:
/// registry_contract! {
///     mod: interpreter,
///     wasm_name: "perch-interpreter",
///     client: perch_interpreter::PolicyClient,
///     hash: "9f3c…",
/// }
/// ```
#[proc_macro]
pub fn registry_contract(input: TokenStream) -> TokenStream {
    let spec = parse_macro_input!(input as RegistrySpec);
    expand(&spec).into()
}

/// Which derivation the generated `address()` performs. Both end at
/// `deployer(registry, salt).deployed_address()`; they differ only in the salt.
enum Mode {
    /// Content-addressed: `salt == wasm_hash`. `WasmName` names the published
    /// wasm; the hash is pinned — from a compile-time literal (`hash:`) or the
    /// sha256 of a local wasm file (`wasm_file:`, computed at build time) — or,
    /// when neither is given, fetched at call time (runtime). This is how a
    /// stateless singleton (compiler, interpreter) is resolved from the registry
    /// it was `deploy_stateless`'d in.
    Content {
        wasm_name: LitStr,
        hash: Option<[u8; 32]>,
    },
    /// Name-salted: `salt == sha256(normalized_name)` — the base registry
    /// `deploy` convention. This is how a *named* deploy (e.g. a subregistry
    /// under its parent) is resolved from the parent registry's id.
    Named { deploy_name: String },
}

/// Parsed `registry_contract! { … }` invocation.
struct RegistrySpec {
    /// Name of the generated module (`mod:`).
    module: Ident,
    /// Which salt the derivation uses (`wasm_name:`/`hash:` vs `deploy_name:`).
    mode: Mode,
    /// Path to the typed client returned by `client()` (`client:`). Optional:
    /// omit it for address-only resolution (no `client()` is generated) — e.g.
    /// resolving a contract used purely as an address, like an interpreter
    /// attached as a policy-map key.
    client: Option<Path>,
}

impl Parse for RegistrySpec {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Name-only form, à la `import_contract_client!`: a bare wasm name (ident
        // or string literal, optional channel prefix + `@version`). The module is
        // derived from the name, and the pin is the sha256 of the wasm looked up
        // at `wasm/<leaf>.wasm`. The keyed `{ mod: … }` form always leads with the
        // `mod` keyword, so its absence selects this form.
        if !input.peek(Token![mod]) {
            return parse_named(input);
        }

        let mut module: Option<Ident> = None;
        let mut wasm_name: Option<LitStr> = None;
        let mut deploy_name: Option<LitStr> = None;
        let mut client: Option<Path> = None;
        let mut hash: Option<[u8; 32]> = None;
        let mut wasm_file: Option<LitStr> = None;

        while !input.is_empty() {
            // `mod` is a keyword, so parse the key with `parse_any`.
            let key = Ident::parse_any(input)?;
            input.parse::<Token![:]>()?;

            match key.to_string().as_str() {
                "mod" => {
                    if module.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `mod`"));
                    }
                    module = Some(Ident::parse_any(input)?);
                }
                "wasm_name" => {
                    if wasm_name.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `wasm_name`"));
                    }
                    wasm_name = Some(input.parse()?);
                }
                "deploy_name" => {
                    if deploy_name.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `deploy_name`"));
                    }
                    deploy_name = Some(input.parse()?);
                }
                "client" => {
                    if client.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `client`"));
                    }
                    client = Some(input.parse()?);
                }
                "hash" => {
                    if hash.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `hash`"));
                    }
                    let lit: LitStr = input.parse()?;
                    hash = Some(parse_hash(&lit)?);
                }
                "wasm_file" => {
                    if wasm_file.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `wasm_file`"));
                    }
                    wasm_file = Some(input.parse()?);
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown key `{other}`; expected one of `mod`, `wasm_name`, \
                             `deploy_name`, `client`, `hash`, `wasm_file`"
                        ),
                    ));
                }
            }

            // Optional trailing comma between (and after) fields.
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        let span = input.span();
        let module = module.ok_or_else(|| syn::Error::new(span, "missing required key `mod`"))?;

        // Exactly one salt source: content-addressed (`wasm_name`) XOR
        // name-salted (`deploy_name`). `hash:`/`wasm_file:` only apply to the
        // former, and are themselves mutually exclusive.
        let mode = match (wasm_name, deploy_name) {
            (Some(_), Some(d)) => {
                return Err(syn::Error::new(
                    d.span(),
                    "`wasm_name` and `deploy_name` are mutually exclusive — pick one salt source",
                ))
            }
            (None, None) => {
                return Err(syn::Error::new(
                    span,
                    "missing a salt source: give `wasm_name` (content-addressed) or \
                     `deploy_name` (name-salted)",
                ))
            }
            (Some(wasm_name), None) => {
                let hash =
                    match (hash, &wasm_file) {
                        (Some(_), Some(f)) => return Err(syn::Error::new(
                            f.span(),
                            "`hash` and `wasm_file` are mutually exclusive — a pin comes from one \
                             or the other",
                        )),
                        // `wasm_file:` — hash a local wasm at build time (its sha256
                        // is the content-address salt). A missing file is a build
                        // error telling you to fetch it.
                        (None, Some(f)) => Some(hash_wasm_at(&f.value(), f.span())?),
                        (h, None) => h,
                    };
                Mode::Content { wasm_name, hash }
            }
            (None, Some(deploy_name)) => {
                if hash.is_some() || wasm_file.is_some() {
                    return Err(syn::Error::new(
                        deploy_name.span(),
                        "`hash`/`wasm_file` are only valid with `wasm_name` (content-addressed mode)",
                    ));
                }
                Mode::Named {
                    deploy_name: normalize_name(&deploy_name.value()),
                }
            }
        };

        Ok(RegistrySpec {
            module,
            mode,
            client,
        })
    }
}

/// Parse the name-only `registry_contract!(<name>)` form, à la
/// `import_contract_client!`. `<name>` is either a **bare ident** matching the
/// crate (`perch_doc_compiler`) — the module is that ident and the wasm/registry
/// name is it with `_`→`-` — or a **string literal** (`"perch-doc-compiler"`,
/// optional channel prefix and `@version`) — the module is the leaf with
/// `-`→`_`. The pin is the sha256 of the wasm at `wasm/<leaf>[_<version>].wasm`
/// (relative to the crate), which must exist — fetch it first.
fn parse_named(input: ParseStream) -> syn::Result<RegistrySpec> {
    // (registry/wasm name, version, module ident string, span)
    let (name_part, version, mod_name, span) = if input.peek(LitStr) {
        let lit: LitStr = input.parse()?;
        let (np, ver) = match lit.value().split_once('@') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (lit.value(), None),
        };
        let leaf = np.rsplit('/').next().unwrap_or(&np).replace('-', "_");
        (np, ver, leaf, lit.span())
    } else {
        // Bare ident matches the crate name; the registry/wasm name uses hyphens.
        let id: Ident = input.parse()?;
        (
            id.to_string().replace('_', "-"),
            None,
            id.to_string(),
            id.span(),
        )
    };
    if input.peek(Token![,]) {
        input.parse::<Token![,]>()?;
    }
    if !input.is_empty() {
        return Err(input.error("the name-only form takes a single wasm name and nothing else"));
    }
    if name_part.is_empty() {
        return Err(syn::Error::new(span, "empty wasm name"));
    }

    let module = syn::parse_str::<Ident>(&mod_name)
        .map_err(|_| syn::Error::new(span, format!("{mod_name:?} is not a valid module name")))?;
    let leaf = name_part.rsplit('/').next().unwrap_or(&name_part);
    let file = match &version {
        Some(v) => format!("wasm/{leaf}_{}.wasm", v.replace('.', "_")),
        None => format!("wasm/{leaf}.wasm"),
    };
    let hash = hash_wasm_at(&file, span)?;
    Ok(RegistrySpec {
        module,
        mode: Mode::Content {
            wasm_name: LitStr::new(&name_part, span),
            hash: Some(hash),
        },
        client: None,
    })
}

/// Read a local wasm file at macro-expansion (build) time and return its sha256 —
/// the digest the registry stores as the `deploy_stateless` content-address salt.
/// `rel` is relative to the invoking crate's `CARGO_MANIFEST_DIR`. A missing file
/// is a **build error** naming it, so resolution is pinned to a wasm you have on
/// disk (fetch it first) rather than silently reaching the network.
fn hash_wasm_at(rel: &str, span: proc_macro2::Span) -> syn::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let manifest = std::env::var("CARGO_MANIFEST_DIR").map_err(|_| {
        syn::Error::new(
            span,
            "CARGO_MANIFEST_DIR unset — cannot resolve the wasm path",
        )
    })?;
    let path = std::path::Path::new(&manifest).join(rel);
    let bytes = std::fs::read(&path).map_err(|e| {
        syn::Error::new(
            span,
            format!(
                "wasm {rel:?} not found ({e}).\n\
                 Fetch the published wasm to {path} first — e.g. run\n\
                 `scripts/fetch-infra-wasm.sh` (or\n\
                 `stellar registry download <wasm-name> --out-file {path}`).",
                path = path.display(),
            ),
        )
    })?;
    Ok(Sha256::digest(&bytes).into())
}

/// Decode a `hash:` literal (64 hex chars, optional `0x` prefix) to 32 bytes.
fn parse_hash(lit: &LitStr) -> syn::Result<[u8; 32]> {
    let raw = lit.value();
    let hex = raw.strip_prefix("0x").unwrap_or(&raw);
    if hex.len() != 64 {
        return Err(syn::Error::new(
            lit.span(),
            format!(
                "`hash` must be 32 bytes (64 hex chars), got {} chars",
                hex.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])
            .ok_or_else(|| syn::Error::new(lit.span(), "`hash` contains a non-hex character"))?;
        let lo = hex_val(bytes[2 * i + 1])
            .ok_or_else(|| syn::Error::new(lit.span(), "`hash` contains a non-hex character"))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Canonicalize a registry name to the form the registry hashes for its deploy
/// salt: lowercase ASCII, `_` → `-`. Mirrors the registry's `NormalizedName`
/// (`sha256` of this string is the name-salt). Keyword rejection and full
/// validation are the registry's job at deploy time, not the resolver's.
fn normalize_name(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '_' => '-',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

fn expand(spec: &RegistrySpec) -> TokenStream2 {
    let module = &spec.module;

    // `client()` is only emitted when a `client:` path was given. Address-only
    // callers (e.g. resolving an interpreter used solely as a policy-map key, or
    // a subregistry we only need the address of) omit it and link no client type.
    let client_item = spec.client.as_ref().map(|client| {
        quote! {
            /// A typed client bound to the derived address.
            pub fn client<'a>(
                env: &::soroban_sdk::Env,
                registry: &::soroban_sdk::Address,
            ) -> #client<'a> {
                #client::new(env, &address(env, registry))
            }
        }
    });

    // Name-salted mode: `salt == sha256(normalized_name)`, the base `deploy`
    // convention — resolves a *named* deploy (e.g. a subregistry) from its
    // parent registry's id. `registry` is the PARENT here.
    let deploy_name = match &spec.mode {
        Mode::Named { deploy_name } => Some(deploy_name.clone()),
        Mode::Content { .. } => None,
    };
    if let Some(deploy_name) = deploy_name {
        return quote! {
            #[allow(dead_code, clippy::all)]
            pub mod #module {
                /// The normalized registry name this module resolves.
                pub const DEPLOY_NAME: &str = #deploy_name;

                /// Derive this named deploy's address from its parent registry —
                /// pure, offline: `salt == sha256(DEPLOY_NAME)`, exactly the base
                /// `deploy` convention. `registry` is the PARENT registry.
                pub fn address(
                    env: &::soroban_sdk::Env,
                    registry: &::soroban_sdk::Address,
                ) -> ::soroban_sdk::Address {
                    let salt = env
                        .crypto()
                        .sha256(&::soroban_sdk::Bytes::from_slice(env, DEPLOY_NAME.as_bytes()))
                        .to_bytes();
                    env.deployer()
                        .with_address(registry.clone(), salt)
                        .deployed_address()
                }

                #client_item
            }
        };
    }

    // Content-addressed mode below (`salt == wasm_hash`).
    let Mode::Content { wasm_name, hash } = &spec.mode else {
        unreachable!("named mode handled above");
    };

    // `hash()` accessor + the salt expression `address()`/`client()` derive from.
    // Both sub-modes end at the same pure derivation:
    //     env.deployer().with_address(registry.clone(), <salt>).deployed_address()
    // where <salt> is the contract's wasm hash (perch's stateless-singleton
    // deploy convention: salt == wasm hash, so the address is a pure function of
    // (registry id, wasm hash) with no on-chain lookup).
    let (hash_items, derive_impl) = if let Some(bytes) = hash {
        // ---- Pinned mode: compile-time hash literal, zero XCC, fully offline.
        let byte_lits = bytes.iter().map(|b| quote!(#b));
        let hash_items = quote! {
            /// The pinned wasm hash, as raw bytes.
            pub const WASM_HASH: [u8; 32] = [ #(#byte_lits),* ];

            /// The pinned wasm hash as a `BytesN<32>`.
            #[inline]
            pub fn hash(env: &::soroban_sdk::Env) -> ::soroban_sdk::BytesN<32> {
                ::soroban_sdk::BytesN::from_array(env, &WASM_HASH)
            }
        };
        let derive_impl = quote! {
            /// Derive this contract's address from the registry id — pure, offline.
            pub fn address(
                env: &::soroban_sdk::Env,
                registry: &::soroban_sdk::Address,
            ) -> ::soroban_sdk::Address {
                env.deployer()
                    .with_address(registry.clone(), hash(env))
                    .deployed_address()
            }
        };
        (hash_items, derive_impl)
    } else {
        // ---- Runtime mode: XCC `fetch_hash(wasm_name)` on the registry, then derive.
        let hash_items = quote! {
            /// Typed client for the registry's `Publishable::fetch_hash`, used to
            /// resolve the current wasm hash for `WASM_NAME` at call time.
            #[::soroban_sdk::contractclient(name = "RegistryPublishableClient")]
            pub trait RegistryPublishable {
                fn fetch_hash(
                    env: &::soroban_sdk::Env,
                    wasm_name: ::soroban_sdk::String,
                    version: ::core::option::Option<::soroban_sdk::String>,
                ) -> ::soroban_sdk::BytesN<32>;
            }

            /// Fetch the current wasm hash from the registry via cross-contract
            /// call. Tracks the registry's latest published version (`version:
            /// None`). Panics (fail closed) if the name is not published.
            pub fn hash(
                env: &::soroban_sdk::Env,
                registry: &::soroban_sdk::Address,
            ) -> ::soroban_sdk::BytesN<32> {
                let wasm_name = ::soroban_sdk::String::from_str(env, WASM_NAME);
                RegistryPublishableClient::new(env, registry)
                    .fetch_hash(&wasm_name, &::core::option::Option::None)
            }
        };
        let derive_impl = quote! {
            /// Derive this contract's address: XCC-fetch the current hash from the
            /// registry, then derive. One cross-contract call per invocation
            /// unless you memoize via [`address_memoized`].
            pub fn address(
                env: &::soroban_sdk::Env,
                registry: &::soroban_sdk::Address,
            ) -> ::soroban_sdk::Address {
                env.deployer()
                    .with_address(registry.clone(), hash(env, registry))
                    .deployed_address()
            }

            /// Instance-storage-memoized variant of [`address`]. Caches the
            /// derived address under `WASM_NAME` so repeated resolutions within a
            /// contract skip the `fetch_hash` XCC.
            ///
            /// Caveat: the cache does NOT observe registry version bumps. Call
            /// [`clear_memo`] after a known interpreter/compiler upgrade, or use
            /// [`address`] directly where version tracking matters.
            pub fn address_memoized(
                env: &::soroban_sdk::Env,
                registry: &::soroban_sdk::Address,
            ) -> ::soroban_sdk::Address {
                let key = ::soroban_sdk::String::from_str(env, WASM_NAME);
                if let ::core::option::Option::Some(addr) = env
                    .storage()
                    .instance()
                    .get::<::soroban_sdk::String, ::soroban_sdk::Address>(&key)
                {
                    return addr;
                }
                let addr = address(env, registry);
                env.storage().instance().set(&key, &addr);
                addr
            }

            /// Drop any address memoized by [`address_memoized`].
            pub fn clear_memo(env: &::soroban_sdk::Env) {
                let key = ::soroban_sdk::String::from_str(env, WASM_NAME);
                env.storage().instance().remove(&key);
            }
        };
        (hash_items, derive_impl)
    };

    quote! {
        #[allow(dead_code, clippy::all)]
        pub mod #module {
            /// The registry wasm name this module resolves.
            pub const WASM_NAME: &str = #wasm_name;

            #hash_items

            #derive_impl

            #client_item
        }
    }
}
