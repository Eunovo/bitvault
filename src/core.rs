use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::opcodes::all::{OP_CSV, OP_DROP};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::{script, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};
use secp256k1::{Secp256k1, XOnlyPublicKey, KeyPair};

use crate::bip119::get_standard_template_hash;
use crate::constants::OP_CTV;

pub struct Vault {
    pub recover_key: XOnlyPublicKey,
    pub recover_script: ScriptBuf,
    pub spend_delay: u16,
    pub trigger_script: ScriptBuf,
    pub unvault_key: KeyPair,
    pub vault_script: ScriptBuf,
}

impl Vault {
    pub fn create_taproot_spend_info(&self) -> TaprootSpendInfo {
        let secp = Secp256k1::new();
        TaprootBuilder::new()
            .add_leaf(1, self.recover_script.clone())
            .expect("Should add recovery script")
            .add_leaf(1, self.trigger_script.clone())
            .expect("Should add trigger script")
            .finalize(&secp, self.recover_key)
            .expect("Should be finalizable")
    }
}

pub struct VaultTrigger<'a> {
    pub target_hash: [u8; 32],
    pub trigger_script: ScriptBuf,
    pub vault: &'a Vault,
    pub withdraw_script: ScriptBuf,
    pub withdraw_template: Transaction,
}

impl VaultTrigger<'_> {
    pub fn new(vault: &Vault) -> VaultTrigger {
        let secp = Secp256k1::new();

        let spend_delay = Sequence::from_height(vault.spend_delay);
        let withdraw_template = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: spend_delay,
                witness: Witness::new(),
            }],
            output: vec![],
        };

        let withdraw_script = script::Builder::new()
            .push_slice(get_standard_template_hash(&withdraw_template, 0))
            .push_sequence(spend_delay)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CTV.into())
            .into_script();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(1, vault.recover_script.clone())
            .expect("Should add recovery script")
            .add_leaf(1, withdraw_script.clone())
            .expect("Should add trigger script")
            .finalize(&secp, vault.recover_key)
            .expect("Should be finalizable");

        let trigger_script_pub_key = ScriptBuf::new_v1_p2tr(
            &secp,
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
        );

        let target_hash = get_standard_template_hash(&withdraw_template, 0);

        VaultTrigger {
            target_hash,
            trigger_script: trigger_script_pub_key,
            vault,
            withdraw_script,
            withdraw_template,
        }
    }
}
