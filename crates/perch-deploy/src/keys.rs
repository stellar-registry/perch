//! Seed-key handling. Seeds arrive ONLY via environment variables — argv leaks
//! through `ps`, so no CLI flag ever carries key material. One S… seed yields
//! both the auth-entry signer (raw ed25519 over the OZ digest) and the
//! fee-paying G-account for the envelope.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;

pub struct SeedKey {
    pub signing: SigningKey,
    /// The 32-byte ed25519 public key derived from the seed.
    pub public: [u8; 32],
}

impl SeedKey {
    pub fn from_env(var: &str) -> Result<Self> {
        let seed = std::env::var(var)
            .with_context(|| format!("{var} not set (expects an S… ed25519 seed, env only)"))?;
        let sk = match stellar_strkey::Strkey::from_string(seed.trim()) {
            Ok(stellar_strkey::Strkey::PrivateKeyEd25519(k)) => k,
            Ok(_) => bail!("{var} is a strkey but not an S… ed25519 seed"),
            Err(e) => bail!("{var} does not parse as a strkey: {e:?}"),
        };
        let signing = SigningKey::from_bytes(&sk.0);
        let public = signing.verifying_key().to_bytes();
        Ok(Self { signing, public })
    }

    /// The G… account funded to pay fees — same key pair as the auth signer.
    pub fn account(&self) -> String {
        // strkey 0.0.16 returns a heapless string; widen to an owned String.
        stellar_strkey::ed25519::PublicKey(self.public)
            .to_string()
            .as_str()
            .into()
    }
}
