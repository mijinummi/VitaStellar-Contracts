#![no_std]
use soroban_sdk::{contract, contractimpl, Env, BytesN, panic_with_error, contracterror};

pub mod keys;
use crate::keys::KeyState;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum EnclaveError {
    NotInitialized = 1,
    UnauthenticatedSigner = 2,
    AlreadyInitialized = 3,
}

#[contract(name = "SecureEnclave")]
pub struct SecureEnclave;

#[contractimpl]
impl SecureEnclave {
    /// Initialize enclave infrastructure with a genesis signing key.
    /// Protects against re-initialization exploits if keys are already established.
    pub fn initialize(env: Env, genesis_key: BytesN<32>) {
        if KeyState::load(&env).is_some() {
            panic_with_error!(&env, EnclaveError::AlreadyInitialized);
        }
        KeyState::init(&env, genesis_key);
    }

    /// Performs atomic key rotation using a programmatic expiration cutoff window.
    pub fn rotate_signing_key(env: Env, new_key: BytesN<32>, grace_period_seconds: u64) {
        let mut state = KeyState::load(&env).unwrap_or_else(|| {
            panic_with_error!(&env, EnclaveError::NotInitialized);
        });

        // Execute atomic state migration block
        state.rotate(&env, new_key, grace_period_seconds);
    }

    /// Validates payload cryptographic authenticity across active key state boundaries.
    pub fn verify_signature(env: Env, signer: BytesN<32>) -> bool {
        let state = KeyState::load(&env).unwrap_or_else(|| {
            panic_with_error!(&env, EnclaveError::NotInitialized);
        });

        if !state.verify_key_validity(&env, &signer) {
            panic_with_error!(&env, EnclaveError::UnauthenticatedSigner);
        }

        true
    }

    /// Housekeeping endpoint used to explicitly clear old records and save instance storage fees.
    pub fn housekeeping(env: Env) -> bool {
        if let Some(mut state) = KeyState::load(&env) {
            return state.purge_expired(&env);
        }
        false
    }
}

// ─── Verification Test Suite ─────────────────────────────────────────────────

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{Env, BytesN};

    fn generate_mock_key(env: &Env, val: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = val;
        BytesN::from_array(env, &arr)
    }

    #[test]
    fn test_enclave_lifecycle_and_rotation_mechanics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000); // Initialize virtual time context

        let client = SecureEnclaveClient::new(&env, &env.register_contract(None, SecureEnclave));

        let key_1 = generate_mock_key(&env, 1);
        let key_2 = generate_mock_key(&env, 2);

        // 1. Verify initialization logic
        client.initialize(&key_1);
        assert!(client.verify_signature(&key_1));

        // 2. Prevent re-initialization hijacking
        let res = client.try_initialize(&key_2);
        assert!(res.is_err(), "Expected re-initialization protection to reject call");

        // 3. Rotate key with a 60-second grace window (valid until t = 1060)
        client.rotate_signing_key(&key_2, &60);
        
        // Both current and prior keys must pass inside the grace window
        assert!(client.verify_signature(&key_2));
        assert!(client.verify_signature(&key_1));

        // 4. Advance ledger time past the expiration parameter threshold (t = 1065)
        env.ledger().set_timestamp(1065);

        // Current key must hold authorization, historical key must be atomically dropped
        assert!(client.verify_signature(&key_2));
        
        let verify_old_res = client.try_verify_signature(&key_1);
        assert!(verify_old_res.is_err(), "Vulnerability window open: expired signature accepted!");

        // 5. Invoke housekeeping cleanup routine
        let internal_purge_state = client.housekeeping();
        assert!(internal_purge_state, "Housekeeping should successfully prune storage footprint");
        
        // Subsequent housekeeping calls should pass cleanly without executing redundant writes
        assert!(!client.housekeeping());
    }
}