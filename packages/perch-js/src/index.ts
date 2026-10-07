// @stellar-registry/perch — TypeScript surface for perch policy documents.
//
// Shipped (this milestone): fail-closed schema mirroring perch-ir, canonical
// JSON + doc_hash and the rule_hash/config_hash fragment hashes byte-identical
// to the Rust model (parity-tested against the shared golden fixtures), and a
// fluent builder producing validated documents.
//
// The consumer interface (#108): revision-consistent account reads, rule
// selection by name and scope, the signing digest and AuthPayload, document
// limits, typed errors, and the apply lifecycle. Every Perch hash and
// authorization encoding a wallet needs lives here, pinned against vectors the
// Rust suite writes.
//
// Planned (tracking issue #8, gated on perch-compile #7 + the interpreter):
//   - compile() with byte-identical output vs the Rust compiler

export {
  canonicalJson,
  docHash,
  ruleHash,
  configHash,
  CANON_VERSION,
  RULE_HASH_DOMAIN,
  CONFIG_HASH_DOMAIN,
} from './canonical.js';
export {
  ACK_SENTINEL,
  policyDocSchema,
  parsePolicyDoc,
  parsePolicyDocJson,
  type PolicyDoc,
  type SignerDecl,
  type Scope,
  type Principals,
  type Rule,
  type ArgConstraint,
  type ArgPred,
  type CapConstraint,
} from './schema.js';
export {
  requestToPolicyDoc,
  type PolicyRequest,
  type Permission,
  type PermissionScope,
} from './request.js';
export {
  policy,
  delegated,
  external,
  isSelf,
  addressEq,
  stringIn,
  stringPrefix,
  u32Eq,
  PolicyBuilder,
  RuleBuilder,
  type SignerSpec,
  type CapSpec,
  type RecoveryModeSpec,
  type RecoverySpec,
  type ZkFactorSpec,
} from './builder.js';
export {
  addressPayload,
  credentialFingerprint,
  encodeCredential,
  encodeReplacementSet,
  encodeStatement,
  replacementsHash,
  statementDigest,
  zkStatementFields,
  type Credential,
  type RecoveryAction,
  type RecoveryStatement,
  type Replacement,
  type ReplacementSet,
  type StatementSubject,
} from './statement.js';
export {
  signingDigest,
  buildAuthPayload,
  authPayload,
  authPayloadXdr,
  ruleIdsXdr,
  compareSigners,
  type AuthPayload,
  type SignerKey,
  type SignerSignature,
} from './auth.js';
export {
  readSnapshot,
  assertRevision,
  checkCapabilities,
  LedgerClock,
  type AccountReader,
  type AccountConfiguration,
  type AccountCapabilities,
  type InstalledRule,
  type FreezeGate,
  type Read,
  type Snapshot,
  type SnapshotOptions,
} from './snapshot.js';
export {
  selectRules,
  selectRecoveryRule,
  resolveRule,
  type RuleRef,
  type RuleScope,
  type RuleSelection,
} from './selection.js';
export { checkLimits, decodeDocLimits, type FlatDocLimits } from './limits.js';
export {
  PerchError,
  StaleRevision,
  StaleSelection,
  OverLimits,
  AccountFrozen,
  InconsistentRead,
  RuleNotFound,
  UnsupportedCapability,
  Aborted,
  ERROR_CODES,
  mapSubmissionError,
} from './errors.js';
export {
  applyDocument,
  oneTransactionBackend,
  type ApplyBackend,
  type ApplyStep,
  type PreparedStep,
  type SubmittedStep,
  type ApplyCallbacks,
  type ApplyEvent,
  type ApplyOperation,
  type ApplyOptions,
  type ApplyPhase,
  type ApplyResult,
  type ApplyDocTransport,
  type FeeEstimate,
  type SignRequest,
} from './apply.js';
export {
  accountReader,
  decodeConfiguration,
  decodeCapabilities,
  type AccountBindings,
  type CompilerBindings,
  type Simulated,
} from './bindings.js';
