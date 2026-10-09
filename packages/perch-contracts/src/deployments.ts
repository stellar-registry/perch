// GENERATED FILE — do not edit by hand. Regenerate with
// scripts/bindings-contracts.sh from deployments/testnet.json.

import type { Deployment } from "./deployment.js";

export const testnet: Deployment = {
  "schema": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "channel": "beta",
  "deployed_at": "2026-10-09T21:39:53Z",
  "deployed_ledger": 5111647,
  "source": {
    "commit": "7ae915dc1ac6ae36cacf6db87794b056923d3b1f",
    "dirty": false
  },
  "toolchain": {
    "builder": "scaffold",
    "rustc": "rustc 1.97.1 (8bab26f4f 2026-07-14)",
    "stellar": "stellar 27.0.0 (5a7c5fe76530bf4248477ac812fc757146b98cc4)",
    "scaffold": "scaffold 0.0.27 (stellar-scaffold-cli-v0.0.27-0-g6f1f06c3e8d2cf82573ec214b20d1550e9ce326b)"
  },
  "registry": {
    "id": "CCUC5RDRGRFFC5VGG7HCB3OMNNSYDFAQOSA7SBGYUM2GDXAJBUWI5TFQ",
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
      "version": "0.3.1",
      "wasm": "perch_doc_compiler.wasm",
      "sha256": "e0f8aacd3ffba3e5ceb2373049319e62cb238d77280d1303e99074b68d6dfdad",
      "bytes": 107799,
      "tier": 0,
      "pins": {},
      "address": "CDHZT7NLQDPMWCUDNUVCYC2EAMGRFWABQO5WDSRJGDQVIDHOWQB2FANB"
    },
    "perch-interpreter": {
      "version": "0.1.3",
      "wasm": "perch_interpreter.wasm",
      "sha256": "2254f17dd722e5113caee901be96849c13e5a6853a6213d62473abe637ae33e1",
      "bytes": 16954,
      "tier": 0,
      "pins": {},
      "address": "CAI6RPWAJ7Z6MP3HLGMTD3W4P4DTD6BEKPFV7XF6VANC2H7XYAQHIXHP"
    },
    "perch-spending-limit": {
      "version": "0.1.2",
      "wasm": "perch_spending_limit.wasm",
      "sha256": "f2f0560ce501ab59144ed71a10349b30bcefaf344ca121c0bd9841577b83c2b7",
      "bytes": 12571,
      "tier": 0,
      "pins": {},
      "address": "CCVXXCAKMROSWAH6QKZ2PUMMH3QUUEUERJQ3CI4XMAWVOMTKKJHYSMTF"
    },
    "perch-ed25519-verifier": {
      "version": "10.0.0",
      "wasm": "perch_ed25519_verifier.wasm",
      "sha256": "851cb7bc36f7917548431cc1490880488f165264516aaf6bd72b93c31b6b39cc",
      "bytes": 1411,
      "tier": 0,
      "pins": {},
      "address": "CA3WZODTJPP45D3IJDWRF2ZKHUJ7E2X5HB3GYM75KPIHWPSD6NRMQIUO"
    },
    "perch-webauthn-verifier": {
      "version": "0.1.0",
      "wasm": "perch_webauthn_verifier.wasm",
      "sha256": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e",
      "bytes": 11783,
      "tier": 0,
      "pins": {},
      "address": "CBCCINHRMS3COAV5RHTCUASZLOEC52FCOBR3HMU4FKWJTAHWZTVFTHHY"
    },
    "perch-zk-pool": {
      "version": "0.1.1",
      "wasm": "perch_zk_pool.wasm",
      "sha256": "5389aef52582831184715bd06ff34e6265800e4b439536af6664882498626105",
      "bytes": 46179,
      "tier": 0,
      "pins": {},
      "address": "CB46EOGM6FSSHO2TNKFWZF5AOIDROPNE6QW75XBKETX5IS757B25WK2Y"
    },
    "perch-zk-adapter": {
      "version": "0.1.1",
      "wasm": "perch_zk_adapter.wasm",
      "sha256": "8a1deec2bbc9ec5d43dbbea7ed91bbd1b4c75397d1f6231e403ff520c8255057",
      "bytes": 68502,
      "tier": 0,
      "pins": {},
      "address": "CBGN355IPW63XPNOSG4O3EZD46ASBXCM5W55PQHEZXJYAFZXN23BNAWC"
    },
    "perch-recovery": {
      "version": "0.1.1",
      "wasm": "perch_recovery.wasm",
      "sha256": "fb4425cf9e59ffc90122e34831614961ee65ebc0551671d1d0c9ae6ce4456afe",
      "bytes": 67108,
      "tier": 0,
      "pins": {},
      "address": "CDIGZVWVXJT2PVDIAUKLX62LW7DNJBC6SZUSR6SLQ6MNICGCGZ6EEXPR"
    },
    "perch-account": {
      "version": "0.3.1",
      "wasm": "perch_account.wasm",
      "sha256": "bbb30174bbd85a2956a2f6146a156769621254011a6bdcac707cf787ce7bcd52",
      "bytes": 69269,
      "tier": 1,
      "pins": {
        "perch-doc-compiler": "e0f8aacd3ffba3e5ceb2373049319e62cb238d77280d1303e99074b68d6dfdad",
        "perch-interpreter": "2254f17dd722e5113caee901be96849c13e5a6853a6213d62473abe637ae33e1",
        "perch-spending-limit": "f2f0560ce501ab59144ed71a10349b30bcefaf344ca121c0bd9841577b83c2b7"
      }
    },
    "perch-account-factory": {
      "version": "0.1.1",
      "wasm": "perch_account_factory.wasm",
      "sha256": "b71bd8881bd84798493e9088c30fbd21b9f397ed8cdada1a363e84cd53343a42",
      "bytes": 4696,
      "tier": 2,
      "pins": {
        "perch-account": "bbb30174bbd85a2956a2f6146a156769621254011a6bdcac707cf787ce7bcd52",
        "perch-webauthn-verifier": "9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e"
      },
      "address": "CDO3IQAR7EF5NFGXK2VI2Q5XU244TDA2IGZUVXHQHOYHHEL3WEJD77OT"
    }
  }
}
;
