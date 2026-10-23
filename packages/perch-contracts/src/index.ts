// `@stellar-registry/perch-contracts`: generated clients for every perch
// stack contract, and the deployments they are at. Each module is also its
// own entry point (`@stellar-registry/perch-contracts/factory`, ...).

export * as account from './account.js';
export * as factory from './factory.js';
export * as recovery from './recovery.js';
export * as pool from './pool.js';
export * as adapter from './adapter.js';
export * as webauthnVerifier from './webauthn-verifier.js';
export * as docCompiler from './doc-compiler.js';
export { addressOf } from './deployment.js';
export type { DeployedContract, Deployment } from './deployment.js';
export { testnet } from './deployments.js';
