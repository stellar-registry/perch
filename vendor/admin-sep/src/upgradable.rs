use crate::AdministratableExtension;
use soroban_sdk::contracttrait;

#[contracttrait]
pub trait Upgradable: AdministratableExtension {
    /// Upgrades the contract to a new hash.
    /// Admin Only.
    fn upgrade(env: &soroban_sdk::Env, new_wasm_hash: &soroban_sdk::BytesN<32>) {
        Self::require_admin(env);
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(new_wasm_hash.clone()));
    }
}
