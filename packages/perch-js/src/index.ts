// @stellar-registry/perch — TypeScript surface for perch policy documents:
// fail-closed schema mirroring perch-ir, canonical JSON + doc_hash and the
// rule_hash/config_hash fragment hashes byte-identical to the Rust model
// (parity-tested against the shared golden fixtures), and a fluent builder
// producing validated documents.
//
// The consumer interface (#108): revision-consistent account reads, rule
// selection by name and scope, the signing digest and AuthPayload, document
// limits, typed errors, and the apply lifecycle. Every Perch hash and
// authorization encoding a wallet needs lives here, pinned against vectors the
// Rust suite writes.
//
// Not here yet (tracking issue #8): compile() with byte-identical output vs
// the Rust compiler.

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
  type AuthRoot,
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
  named,
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
  MAX_VERIFIER_NAME_LEN,
  VERIFIERS_PATH,
  UnverifiedVerifier,
  UnverifiedVerifierReused,
  checkVerifiers,
  deployedAddress,
  isAccountDocument,
  parseVerifierName,
  resolveVerifierName,
  unverifiedReuse,
  unverifiedVerifiers,
  unverifiedWarnings,
  verifierAddress,
  verifierRegistryId,
  type FetchHash,
  type ResolvedVerifier,
  type VerifierWarning,
} from './verifiers.js';
export { OWNER_FNS, selfPinWarnings, type SelfPinWarning } from './grants.js';
export {
  addressPayload,
  credentialFingerprint,
  encodeCredential,
  encodeReplacementSet,
  encodeStatement,
  replacementsHash,
  sortReplacements,
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
  assertSignable,
  frozenAt,
  grantMode,
  checkCapabilities,
  checkDocumentCapabilities,
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
  AuthRootMismatch,
  type AuthorizationCall,
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
  CompilerMismatch,
  ERROR_CODES,
  accountErrorCodes,
  mapSubmissionError,
  type SubmissionFailure,
} from './errors.js';
export {
  decodeDiagnosticEvent,
  accountErrorCodesFromEvents,
  strkey,
  type DiagnosticEvent,
  type DiagnosticValue,
} from './diagnostics.js';
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
  decodeStoredRule,
  decodeStoredGrant,
  readGrantDoc,
  type AccountBindings,
  type CompilerBindings,
  type GrantBindings,
  type Simulated,
} from './bindings.js';
export {
  rebuildGrantDoc,
  GrantNotRebuilt,
  type RebuiltGrant,
  type StoredCond,
  type StoredRule,
  type StoredGrant,
  type StoredVal,
} from './grant.js';
