// GENERATED FILE — do not edit by hand. Regenerate with
// scripts/bindings-contracts.sh from deployments/testnet.json.

import type { Deployment } from "./deployment.js";

export const testnet: Deployment = {
  "schema": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "channel": "beta",
  "deployed_at": "2026-10-07T21:38:59Z",
  "deployed_ledger": 5077086,
  "source": {
    "commit": "aa5a78f13be1ca4943b4f6a6c9e2f356f6d8ccdc",
    "dirty": false
  },
  "toolchain": {
    "builder": "scaffold",
    "rustc": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
    "stellar": "stellar 27.0.0 (5a7c5fe76530bf4248477ac812fc757146b98cc4)",
    "scaffold": "scaffold 0.0.27 (stellar-scaffold-cli-v0.0.27-0-g6f1f06c3e8d2cf82573ec214b20d1550e9ce326b)"
  },
  "registry": {
    "id": "CB4D5F5N3MYMGWOKN5DUEI4LMJ34GBO5WJKTXNOXPNKAEWRCQSQLBEJL",
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
      "sha256": "c48390ed62f941196ee77689c5baa801a9dfba6ced1800e1a6910990dcac5dca",
      "bytes": 107799,
      "tier": 0,
      "pins": {},
      "address": "CDFB7XC4HDQCCMNTV2PWWM33W35UOHEJ2UNXW2QNB3SHPT456KZRY74A"
    },
    "perch-interpreter": {
      "version": "0.1.2",
      "wasm": "perch_interpreter.wasm",
      "sha256": "5498ebbff9ced40b56d5be05271dc44d29a687ad6a37fc0c3f1670c29d4e7406",
      "bytes": 16954,
      "tier": 0,
      "pins": {},
      "address": "CBH2R7E5PKLEQ7OMNYK6BHDWFZM7TJUAONFVFUO4ECACIBORNIGCHXLD"
    },
    "perch-spending-limit": {
      "version": "0.1.1",
      "wasm": "perch_spending_limit.wasm",
      "sha256": "875fdb15f4d412d8eb346db4db1f7113698f4c16207cbef2c6e0b33b8ce86fff",
      "bytes": 12571,
      "tier": 0,
      "pins": {},
      "address": "CAWDTYQ2FMSQCMTRG7DT25UCSTSSSH7QWPX6YJJZWM6KU52ZIHUJSODY"
    },
    "perch-ed25519-verifier": {
      "version": "0.1.1",
      "wasm": "perch_ed25519_verifier.wasm",
      "sha256": "bec62a6e1b0c378d8b68b81bf3b912fada37adf1194354e9f1447f3fa3a6a459",
      "bytes": 1411,
      "tier": 0,
      "pins": {},
      "address": "CCRP6GSBFGJ6DQNMO6N7LDNZNZZ5DHAKIQTGJ4HYMNVSHW3HY74OBHYU"
    },
    "perch-webauthn-verifier": {
      "version": "0.1.0",
      "wasm": "perch_webauthn_verifier.wasm",
      "sha256": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e",
      "bytes": 11783,
      "tier": 0,
      "pins": {},
      "address": "CA2GRIVA5M6QTWEH3TQDBREFIKRKZHQYZJFPWXLATGTVS4NFLEKHLFMH"
    },
    "perch-zk-pool": {
      "version": "0.1.0",
      "wasm": "perch_zk_pool.wasm",
      "sha256": "8cb74d03411201e69c478691820b4d464093e33d27976c6f4ccdc4854b91b640",
      "bytes": 46055,
      "tier": 0,
      "pins": {},
      "address": "CAZF7RWHUP3F2CT3XOXGBGXQRFQEKGMUEAOGDULKMEOKMW6IHFD6KTBH"
    },
    "perch-zk-adapter": {
      "version": "0.1.0",
      "wasm": "perch_zk_adapter.wasm",
      "sha256": "9eae13c48ba63afb8ba6b4e0c9f7e18d3f2e937e798bfafcd350d7fe7029e709",
      "bytes": 68374,
      "tier": 0,
      "pins": {},
      "address": "CBHPOMMRFZBV5347EOFRJD476TMGS2L4QC5KKCYLLERIYLUMCXVFVBVX"
    },
    "perch-recovery": {
      "version": "0.1.0",
      "wasm": "perch_recovery.wasm",
      "sha256": "ad0b9b2587cbd87befb9a3b0ca1b01f42aab200a1d6107a564ecdbcdc1d67771",
      "bytes": 66785,
      "tier": 0,
      "pins": {},
      "address": "CAM67FBUSDD7DLDYU6I4KEYFFTYDVH2PTCY6JG7VCLXCFCW3JICGVYVN"
    },
    "perch-account": {
      "version": "0.3.0",
      "wasm": "perch_account.wasm",
      "sha256": "238ec4b6d6d7c80eea9386affd153dbeb253b5e561d7e0d95c8cd7f4dc76f4ba",
      "bytes": 69253,
      "tier": 1,
      "pins": {
        "perch-doc-compiler": "c48390ed62f941196ee77689c5baa801a9dfba6ced1800e1a6910990dcac5dca",
        "perch-interpreter": "5498ebbff9ced40b56d5be05271dc44d29a687ad6a37fc0c3f1670c29d4e7406",
        "perch-spending-limit": "875fdb15f4d412d8eb346db4db1f7113698f4c16207cbef2c6e0b33b8ce86fff"
      }
    },
    "perch-account-factory": {
      "version": "0.1.0",
      "wasm": "perch_account_factory.wasm",
      "sha256": "82d137c9870a6045e03ee53a5ae5d498f389f48f63c9ac8d046be3c869fa77f1",
      "bytes": 4696,
      "tier": 2,
      "pins": {
        "perch-account": "238ec4b6d6d7c80eea9386affd153dbeb253b5e561d7e0d95c8cd7f4dc76f4ba",
        "perch-webauthn-verifier": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e"
      },
      "address": "CBPAZJVPZZ27GLMXHFTSGFAEA5HCY4MDVVQEC5MGIZGLV3WWEGJJE6SS"
    }
  }
}
;
