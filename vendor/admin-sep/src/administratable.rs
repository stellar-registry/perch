use soroban_sdk::{Address, Env, Symbol, contracttrait, symbol_short};

/// Trait for using an admin address to control access.
#[contracttrait]
pub trait Administratable {
    fn admin(env: &Env) -> soroban_sdk::Address {
        unsafe { admin_from_storage(env).unwrap_unchecked() }
    }

    fn set_admin(env: &Env, new_admin: &soroban_sdk::Address) {
        if let Some(owner) = admin_from_storage(env) {
            owner.require_auth();
        }
        env.storage().instance().set(STORAGE_KEY, new_admin);
    }
}

pub trait AdministratableExtension: Administratable {
    fn require_admin(env: &Env);
}

impl<T: Administratable> AdministratableExtension for T {
    fn require_admin(env: &Env) {
        Self::admin(env).require_auth();
    }
}

fn admin_from_storage(env: &Env) -> Option<Address> {
    env.storage().instance().get(STORAGE_KEY)
}

pub const STORAGE_KEY: &Symbol = &symbol_short!("ADMIN");
