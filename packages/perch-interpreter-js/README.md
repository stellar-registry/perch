# @stellar-registry/perch-interpreter

TypeScript client bindings for the perch interpreter contract
([`crates/perch-interpreter`](../../crates/perch-interpreter)), the deployable
OpenZeppelin `Policy` that evaluates compiled perch constraint programs
on-chain, for OZ smart accounts that attach it as a policy. A Perch account
pins the interpreter (its `infra()` view reports the address) but calls it
from no rule: the account evaluates its rules with rule-eval
([`docs/audit-scope.md`](../../docs/audit-scope.md)).

- `install` / `uninstall`: attach or detach a compiled program for one
  `(account, rule)`. Both require the smart account's own authorization.
  `InstallParams` is the `RpnProgram` plus its provenance: the field named
  `doc_hash` holds the `rule_hash` of the rule the program was compiled from
  (`CANONICAL.md`, "Fragment hashes"), not a whole document's hash.
- `get_program`: read back the stored `InstallParams`, so a client can
  check a program's provenance against the reviewed rule's `rule_hash`.
- `program_version`: the program wire-format version this interpreter
  evaluates. `install` refuses any other version.
- `enforce`: the OZ policy hook, which the smart account invokes; exposed
  for simulation.

```ts
import { Client } from '@stellar-registry/perch-interpreter';

const interpreter = new Client({
  contractId: INTERPRETER_ADDRESS, // resolve via the registry / deployment map
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

const stored = await interpreter.get_program({
  smart_account: ACCOUNT_ADDRESS,
  context_rule_id: 1,
});
```

This package carries no interpreter address. Resolve it from the
content-addressed registry pins. A Perch account
reports the interpreter it pins in its `infra()` view; the recovery-stack
deployment's addresses, its registry included, are in
[`deployments/testnet.json`](../../deployments/testnet.json) and
[`deployments/mainnet.json`](../../deployments/mainnet.json).

The sibling package [`@stellar-registry/perch`](../perch-js) is the off-chain
half: PolicyDoc schema, canonical JSON and hashes (including `ruleHash`),
and the builder. This package is the on-chain client half; the two meet at
the provenance hash in `InstallParams`.

## Generated code

`stellar contract bindings typescript` generates `src/index.ts` from the
scaffold-built interpreter wasm; do not edit it by hand. After any change to
the contract's entry points or `#[contracttype]`s:

```sh
just bindings-interpreter-js
```

then review the diff and rerun the suite. The tests assert the embedded
`ContractSpec` against the frozen golden XDR vectors in
[`testdata/golden/`](../../testdata/golden/README.md) (the TypeScript
check): the two program fixtures encoded through these bindings must
reproduce the `#[contracttype]` bytes the Rust suite pins, byte for byte.

The doc comments in `src/index.ts` come from the contract's embedded spec
and still describe the provenance field as the source document's
`doc_hash`; the description above is the current behaviour.
