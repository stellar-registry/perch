// GENERATED FILE — do not edit by hand. Regenerate with
// scripts/bindings-contracts.sh from deployments/testnet.json.

import type { Deployment } from "./deployment.js";

export const testnet: Deployment = {
  "schema": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "channel": "beta",
  "deployed_at": "2026-10-22T13:41:43Z",
  "deployed_ledger": 5330546,
  "source": {
    "commit": "c135aca277745434f2abf679edd9868c95204b51",
    "dirty": false
  },
  "toolchain": {
    "builder": "scaffold",
    "rustc": "rustc 1.99.1 (58cf8f9c3 2026-10-13)",
    "stellar": "stellar 28.0.0-aha.0 (70667cde89632b363d1c8dfb84ff698cbb646988)",
    "scaffold": "scaffold 0.0.27 (stellar-scaffold-cli-v0.0.27-0-g6f1f06c3e8d2cf82573ec214b20d1550e9ce326b)"
  },
  "registry": {
    "id": "CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM",
    "wasm_hash": "0acc4da2b0b44b70988fe9a3b64b31e7ace166e5a949e9e6846f72c6ce93c055",
    "admin": "GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M",
    "manager": "GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M",
    "root": "CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M"
  },
  "zk": {
    "circuit_id": "9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a",
    "tree_depth": 32,
    "circuit_manifest": "circuits/manifest.json"
  },
  "contracts": {
    "perch-doc-compiler": {
      "version": "0.3.5",
      "wasm": "perch_doc_compiler.wasm",
      "sha256": "2730a7d39d619579bb7873818900fa5f9150d69d49fa1ee3b4a38f61ba768a16",
      "bytes": 109947,
      "tier": 0,
      "pins": {},
      "address": "CAYCPM5O6SGGAZOCCAUJ27CZZ7SMHU4VYSA25ZHDMGKILP4Z5RGF467E"
    },
    "perch-interpreter": {
      "version": "0.1.6",
      "wasm": "perch_interpreter.wasm",
      "sha256": "f884913eba4a9491f8bcf89d1a687381c7c0699b148f98f8dc344e9a6223b26e",
      "bytes": 17999,
      "tier": 0,
      "pins": {},
      "address": "CBOGVUQWY5G7BP7OWEJX3Z5PSZLYJXHM54A7OEMXQQ7ZO4GHHM4WCEAP"
    },
    "perch-spending-limit": {
      "version": "0.1.4",
      "wasm": "perch_spending_limit.wasm",
      "sha256": "8c043dcc24f944d7c3e349fb5fd83cedba4a9124b5791b625bd76b520b0f4a80",
      "bytes": 12923,
      "tier": 0,
      "pins": {},
      "address": "CAG3IDO3FXE2HQVQHRGRBKWGL2IPAA2V6B3UMHES4ZUNS7OEV646HYV5"
    },
    "perch-ed25519-verifier": {
      "version": "10.0.2",
      "wasm": "perch_ed25519_verifier.wasm",
      "sha256": "defdab3434b361272c2461a174b94271a49e67fa0a6714b53689aca32e8d1592",
      "bytes": 1863,
      "tier": 0,
      "pins": {},
      "address": "CC7ZFUIENDZPX3C7R4XTA4LG3PCLJM63UGAFYW5XKN35ACIKHZPEDXOG"
    },
    "perch-webauthn-verifier": {
      "version": "0.1.2",
      "wasm": "perch_webauthn_verifier.wasm",
      "sha256": "f2e1dfce8c496be6d318045bc5a24ac5eb799ada837f92e8032ec953f1994230",
      "bytes": 11825,
      "tier": 0,
      "pins": {},
      "address": "CDEV5YPS5IITPLQPYTKJGWBNZ2YZ7FQZIJNSHUMJRBE4QWYK2IVK4EJT"
    },
    "perch-zk-pool": {
      "version": "0.1.4",
      "wasm": "perch_zk_pool.wasm",
      "sha256": "985660d4a6d6baa31a863158e89b8cbecc37cececd7104382172a1805b7289d5",
      "bytes": 47959,
      "tier": 0,
      "pins": {},
      "address": "CASXCXSBIG6ECB3LO4LCEW6SZIFHZDTJ3PFOZJK5JI56VKXLSZY6J67P"
    },
    "perch-zk-adapter": {
      "version": "0.1.4",
      "wasm": "perch_zk_adapter.wasm",
      "sha256": "95869bab4b89e5a4306ffe0d7a9e91931a56518ef18b3f61e95df86145dda63e",
      "bytes": 69803,
      "tier": 0,
      "pins": {},
      "address": "CDWVAUSTU2DHBBWANQKGSHCXFK5C46WMUEMWRBOV2LBVXQGK4PGIFBQS"
    },
    "perch-recovery": {
      "version": "0.1.5",
      "wasm": "perch_recovery.wasm",
      "sha256": "daaf09d9f73f6890753572b33a5c41a22c2ebf0e9ce29593e8407ff858844eb8",
      "bytes": 68263,
      "tier": 0,
      "pins": {},
      "address": "CBOFO5KWQKCZ7LBS4LDIYXA6LGZSUSA6JKOHHBBL64KQNZLPGDJ252FT"
    },
    "perch-account": {
      "version": "0.5.1",
      "wasm": "perch_account.wasm",
      "sha256": "2c976bfd98678f3b6fcf5514420a81ef5e5b9fc1c5b6c60ec6f2dd64448479d5",
      "bytes": 70702,
      "tier": 1,
      "pins": {
        "perch-doc-compiler": "2730a7d39d619579bb7873818900fa5f9150d69d49fa1ee3b4a38f61ba768a16",
        "perch-interpreter": "f884913eba4a9491f8bcf89d1a687381c7c0699b148f98f8dc344e9a6223b26e",
        "perch-spending-limit": "8c043dcc24f944d7c3e349fb5fd83cedba4a9124b5791b625bd76b520b0f4a80"
      }
    },
    "perch-account-factory": {
      "version": "0.3.1",
      "wasm": "perch_account_factory.wasm",
      "sha256": "6b434991d983063c92a47ba1573514f46e5c2ecb184d8c654af60a637ccd3fc2",
      "bytes": 4533,
      "tier": 2,
      "pins": {
        "perch-account": "2c976bfd98678f3b6fcf5514420a81ef5e5b9fc1c5b6c60ec6f2dd64448479d5",
        "perch-webauthn-verifier": "f2e1dfce8c496be6d318045bc5a24ac5eb799ada837f92e8032ec953f1994230"
      },
      "address": "CC7QOMXP6IJRBE6APO7FVCBCPJTDHP3USE3XSQF7AAXWSJ2DZWDV3YXK"
    }
  }
}
;
