// GENERATED FILE — do not edit by hand. Regenerate with
// scripts/bindings-contracts.sh from deployments/testnet.json.

import type { Deployment } from "./deployment.js";

export const testnet: Deployment = {
  "schema": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "channel": "beta",
  "deployed_at": "2026-10-07T18:23:14Z",
  "deployed_ledger": 5074730,
  "source": {
    "commit": "704aa23f3cebe1e291f70385b4d55f704a30e994",
    "dirty": false
  },
  "toolchain": {
    "builder": "scaffold",
    "rustc": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
    "stellar": "stellar 27.0.0 (5a7c5fe76530bf4248477ac812fc757146b98cc4)",
    "scaffold": "scaffold 0.0.27 (stellar-scaffold-cli-v0.0.27-0-g6f1f06c3e8d2cf82573ec214b20d1550e9ce326b)"
  },
  "registry": {
    "id": "CBU7P2S72OL4TD63OBJC3WYQSJSPKS7WRLDO4YT5STOKH7CSQ54HCUY5",
    "wasm_hash": "4b2d9ea4148474715076e81067cff06b765248d9c4cd7d0e99e53df3e368adec",
    "admin": "GBQQGD4AEWBBAU3TIH56XRHQI5CONAEIOPFMWASOKQMLUEITPZOWQLE7",
    "manager": "GBQQGD4AEWBBAU3TIH56XRHQI5CONAEIOPFMWASOKQMLUEITPZOWQLE7",
    "root": "CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M"
  },
  "zk": {
    "circuit_id": "9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a",
    "tree_depth": 32,
    "circuit_manifest": "circuits/manifest.json"
  },
  "contracts": {
    "perch-doc-compiler": {
      "version": "0.3.0",
      "wasm": "perch_doc_compiler.wasm",
      "sha256": "f04df788c0d5c9bffed53dc39a49ecf5159307f3a6448ec6ab64cdd84c8b05cf",
      "bytes": 106080,
      "tier": 0,
      "pins": {},
      "address": "CCECBBCM5WV6KHZULIO6ORWWBT35ZKVLEJTO6ALIOOULRXAVD7JHICO6"
    },
    "perch-interpreter": {
      "version": "0.1.2",
      "wasm": "perch_interpreter.wasm",
      "sha256": "5498ebbff9ced40b56d5be05271dc44d29a687ad6a37fc0c3f1670c29d4e7406",
      "bytes": 16954,
      "tier": 0,
      "pins": {},
      "address": "CDUU5QEXGCZ5TJNK35WVVSPYURIIFM5H5ZNWJJW3QDSZB57B66C3DNHQ"
    },
    "perch-spending-limit": {
      "version": "0.1.1",
      "wasm": "perch_spending_limit.wasm",
      "sha256": "875fdb15f4d412d8eb346db4db1f7113698f4c16207cbef2c6e0b33b8ce86fff",
      "bytes": 12571,
      "tier": 0,
      "pins": {},
      "address": "CCUM47GUADDA5CQ54CSPPGAKFXGJQHNZYKP7HQH5Z3UX3E2TBTSAINAD"
    },
    "perch-ed25519-verifier": {
      "version": "0.1.1",
      "wasm": "perch_ed25519_verifier.wasm",
      "sha256": "bec62a6e1b0c378d8b68b81bf3b912fada37adf1194354e9f1447f3fa3a6a459",
      "bytes": 1411,
      "tier": 0,
      "pins": {},
      "address": "CDTVGVGYGUVP57ALIMBHH5EVSBPQ2B575AOJP73W3O7QHGFNBFDNLXTD"
    },
    "perch-webauthn-verifier": {
      "version": "0.1.0",
      "wasm": "perch_webauthn_verifier.wasm",
      "sha256": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e",
      "bytes": 11783,
      "tier": 0,
      "pins": {},
      "address": "CCN63JUG7EAMFSQ2VEZA73ZDFDW6WMOCOM67U5Z7ERI5B67KWTMQ6UBG"
    },
    "perch-zk-pool": {
      "version": "0.1.0",
      "wasm": "perch_zk_pool.wasm",
      "sha256": "8cb74d03411201e69c478691820b4d464093e33d27976c6f4ccdc4854b91b640",
      "bytes": 46055,
      "tier": 0,
      "pins": {},
      "address": "CDVEAUJCXT4H3P6PN75JUNWCPJZI26X2T27GI5MZO2KEAKLRSQCDMVH4"
    },
    "perch-zk-adapter": {
      "version": "0.1.0",
      "wasm": "perch_zk_adapter.wasm",
      "sha256": "9eae13c48ba63afb8ba6b4e0c9f7e18d3f2e937e798bfafcd350d7fe7029e709",
      "bytes": 68374,
      "tier": 0,
      "pins": {},
      "address": "CB7PYUMZLBHP3DVT6SF2YVTSTCLSXKZC4EPIII7VHYLJ6BRDJCQZISIU"
    },
    "perch-recovery": {
      "version": "0.1.0",
      "wasm": "perch_recovery.wasm",
      "sha256": "ad0b9b2587cbd87befb9a3b0ca1b01f42aab200a1d6107a564ecdbcdc1d67771",
      "bytes": 66785,
      "tier": 0,
      "pins": {},
      "address": "CCJGLH3SHOVN3ALAJKBMZ2WVA3ISHFE5ENLYTHZBJKWZ2ELMVA4ZHVWN"
    },
    "perch-account": {
      "version": "0.3.0",
      "wasm": "perch_account.wasm",
      "sha256": "7743becf9382698f0a6e36d9987d6bac903ed96ed859c3a93cd4486a9e1474e5",
      "bytes": 64884,
      "tier": 1,
      "pins": {
        "perch-doc-compiler": "f04df788c0d5c9bffed53dc39a49ecf5159307f3a6448ec6ab64cdd84c8b05cf",
        "perch-interpreter": "5498ebbff9ced40b56d5be05271dc44d29a687ad6a37fc0c3f1670c29d4e7406",
        "perch-spending-limit": "875fdb15f4d412d8eb346db4db1f7113698f4c16207cbef2c6e0b33b8ce86fff"
      }
    },
    "perch-account-factory": {
      "version": "0.1.0",
      "wasm": "perch_account_factory.wasm",
      "sha256": "e9005eb5a828d8bf59e63b1885702c8b93dec90bdb02eaf911f347339e765afb",
      "bytes": 4696,
      "tier": 2,
      "pins": {
        "perch-account": "7743becf9382698f0a6e36d9987d6bac903ed96ed859c3a93cd4486a9e1474e5",
        "perch-webauthn-verifier": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e"
      },
      "address": "CCWDMTENTHYEAWO74I7TBWVPDW4XRSO6I5N52IRXMPOPQZ4DLT7WNPUB"
    }
  }
}
;
