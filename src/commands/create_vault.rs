use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::Network::Regtest;
use bitcoin::{script, Address, ScriptBuf, Sequence};
use secp256k1::hashes::sha256;
use secp256k1::{rand, KeyPair, Secp256k1};

use crate::core::{Vault};
use crate::db::{VaultTable, VaultTableRow};
use crate::constants::{ OP_VAULT, OP_VAULT_RECOVER, OP_CTV };

fn tag_engine(tag_name: &str) -> sha256::HashEngine {
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine
}

pub fn create_vault_script() -> Vault {
    let secp = Secp256k1::new();

    // Create recovery and unvault keys
    let recovery_key = KeyPair::new(&secp, &mut rand::thread_rng());
    let unvault_key = KeyPair::new(&secp, &mut rand::thread_rng());

    // Create taproot payment for recovery and unvault keys
    let (recovery_internal_key, _recovery_p) = UntweakedPublicKey::from_keypair(&recovery_key);
    let (unvault_internal_key, _unvault_p) = UntweakedPublicKey::from_keypair(&unvault_key);
    let recovery_p2tr = ScriptBuf::new_v1_p2tr(&secp, recovery_internal_key, None);

    // Create Recovery hash which is tagged hash of recovery script pub key
    let mut recovery_hash_eng = tag_engine("VaultRecoverySPK");
    recovery_hash_eng.input(&recovery_p2tr.as_bytes());
    let recovery_hash = sha256::Hash::from_engine(recovery_hash_eng).to_byte_array();

    // Recovery Script: <recovery_auth_script_pubkey or ""> <recovery_hash> op_vault_recover
    let recovery_script = script::Builder::new()
        .push_slice(recovery_hash)
        .push_opcode(OP_VAULT_RECOVER.into())
        .into_script();

    let spend_delay = 10;
    // let vault_script_str = format!("{OP_CSV}{OP_DROP}{OP_CTV}");
    let vault_script = script::Builder::new()
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_CTV.into())
        .into_bytes();

    let mut vault_script_bytes = PushBytesBuf::new();
    for byte in vault_script {
        vault_script_bytes
            .push(byte)
            .expect("Should be within limit");
    }

    // let trigger_script = format!("{unvault_internal_key}{OP_CHECKSIGVERIFY}{spend_delay} 2 {vault_script_str}{op_vault}");
    let trigger_script = script::Builder::new()
        .push_x_only_key(&unvault_internal_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_sequence(Sequence::from_height(spend_delay))
        .push_int(2)
        .push_slice(vault_script_bytes)
        .push_opcode(OP_VAULT.into())
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, recovery_script.clone())
        .expect("Should add recovery script")
        .add_leaf(1, trigger_script.clone())
        .expect("Should add trigger script")
        .finalize(&secp, recovery_internal_key)
        .expect("Should be finalizable");

    let vault_script = ScriptBuf::new_v1_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    );

    Vault {
        recover_key: recovery_internal_key,
        recover_script: recovery_script,
        spend_delay,
        trigger_script,
        unvault_key,
        vault_script
    }
}

pub fn create_vault(db: VaultTable, name: &String) {
    let vault= create_vault_script();
    let address = Address::from_script(&vault.vault_script, Regtest)
        .expect("Should create address");

    match db.insert(&VaultTableRow(name.to_string(), address.to_string())) {
        Ok(_) => println!("New Vault Address: {address}"),
        Err(e) => eprintln!("Could not save vault: {0}", e.to_string())
    }
}

#[test]
fn test_create_vault() {
    let vault = create_vault_script();
    let address = Address::from_script(&vault.vault_script, Regtest);
    assert!(address.is_ok(), "Should be okay");
}