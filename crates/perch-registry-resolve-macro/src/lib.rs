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
/// registry_contract! {
///     mod: interpreter,
///     wasm_name: "perch-interpreter",
///     client: perch_interpreter::PolicyClient,
///     hash: "9f3c…",   // optional: present => pinned (offline) mode
/// }
/// ```
#[proc_macro]
pub fn registry_contract(input: TokenStream) -> TokenStream {
    let spec = parse_macro_input!(input as RegistrySpec);
    expand(&spec).into()
}

/// Parsed `registry_contract! { … }` invocation.
struct RegistrySpec {
    /// Name of the generated module (`mod:`).
    module: Ident,
    /// The registry wasm name looked up in runtime mode (`wasm_name:`).
    wasm_name: LitStr,
    /// Path to the typed client returned by `client()` (`client:`). Optional:
    /// omit it for address-only resolution (no `client()` is generated) — e.g.
    /// resolving a contract used purely as an address, like an interpreter
    /// attached as a policy-map key.
    client: Option<Path>,
    /// Pinned wasm hash bytes (`hash:`), or `None` for runtime-fetch mode.
    hash: Option<[u8; 32]>,
}

impl Parse for RegistrySpec {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut module: Option<Ident> = None;
        let mut wasm_name: Option<LitStr> = None;
        let mut client: Option<Path> = None;
        let mut hash: Option<[u8; 32]> = None;

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
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown key `{other}`; expected one of `mod`, `wasm_name`, \
                             `client`, `hash`"
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
        Ok(RegistrySpec {
            module: module.ok_or_else(|| syn::Error::new(span, "missing required key `mod`"))?,
            wasm_name: wasm_name
                .ok_or_else(|| syn::Error::new(span, "missing required key `wasm_name`"))?,
            client,
            hash,
        })
    }
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

fn expand(spec: &RegistrySpec) -> TokenStream2 {
    let module = &spec.module;
    let wasm_name = &spec.wasm_name;

    // `client()` is only emitted when a `client:` path was given. Address-only
    // callers (e.g. resolving an interpreter used solely as a policy-map key)
    // omit it and link no client type at all.
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

    // `hash()` accessor + the salt expression `address()`/`client()` derive from.
    // Both modes end at the same pure derivation:
    //     env.deployer().with_address(registry.clone(), <salt>).deployed_address()
    // where <salt> is the contract's wasm hash (perch's stateless-singleton
    // deploy convention: salt == wasm hash, so the address is a pure function of
    // (registry id, wasm hash) with no on-chain lookup).
    let (hash_items, derive_impl) = if let Some(bytes) = spec.hash {
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
