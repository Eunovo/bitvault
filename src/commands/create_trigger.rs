use bitcoin::key::TapTweak;
use bitcoin::script::write_scriptint;
use bitcoin::{
    absolute::LockTime,
    psbt::{self, Input, Psbt, PsbtSighashType},
    sighash::{self, SighashCache, TapSighash, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin::{script, taproot};
use secp256k1::{Secp256k1, XOnlyPublicKey};
use std::collections::BTreeMap;

use crate::core::{Vault, VaultTrigger};

pub fn create_trigger_tranx(
    vault: &Vault,
    amount: u64,
    vault_outpoint: &OutPoint,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let trigger = VaultTrigger::new(vault);
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vault_outpoint.clone(),
            witness: Witness::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(vault.spend_delay),
        }],
        output: vec![TxOut {
            value: amount,
            script_pubkey: trigger.trigger_script,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();
    // let sighash = PsbtSighashType::from;
    let vault_tr = vault.create_taproot_spend_info();
    let vault_trigger_control_block = vault_tr
        .control_block(&(vault.trigger_script.clone(), LeafVersion::TapScript))
        .unwrap();
    let mut tap_scripts = BTreeMap::new();
    tap_scripts.insert(
        vault_trigger_control_block,
        (vault.trigger_script.clone(), LeafVersion::TapScript),
    );

    let input = Input {
        witness_utxo: Some(TxOut {
            value: amount,
            script_pubkey: vault.vault_script.clone(),
        }),
        // sighash_type: TapSighashType::All,
        tap_scripts,
        tap_merkle_root: vault_tr.merkle_root(),
        tap_internal_key: Some(vault.recover_key),
        ..Default::default()
    };
    psbt.inputs = vec![input];
    let unsigned_tx = psbt.unsigned_tx.clone();
    psbt.inputs
        .iter_mut()
        .enumerate()
        .try_for_each::<_, Result<(), Box<dyn std::error::Error>>>(|(vout, input)| {
            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);

            let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
                vout,
                &sighash::Prevouts::All(&[TxOut {
                    value: amount,
                    script_pubkey: vault.vault_script.clone(),
                }]),
                hash_ty,
            )?;

            sign_psbt_taproot(
                &vault.unvault_key,
                input.tap_internal_key.unwrap(),
                Some(vault.trigger_script.as_script().tapscript_leaf_hash()),
                input,
                hash,
                hash_ty,
                &secp,
            );

            Ok(())
        })
        .expect("Should sign inputs");

    psbt.inputs.iter_mut().for_each(|input| {
        let vout_idx = 0;
        let mut script_witness: Witness = Witness::new();
        script_witness.push(bn2vch(-1)); // No revault
        script_witness.push({
            match vout_idx == 0 {
                false => script::Builder::new().push_int(vout_idx).into_bytes(),
                true => vec![],
            }
        });
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        script_witness.push(vault.trigger_script.clone());
        let control_block = vault_tr
            .control_block(&(vault.trigger_script.clone(), LeafVersion::TapScript))
            .unwrap();
        script_witness.push(control_block.serialize());

        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    // EXTRACTOR
    let tx: Transaction = psbt.extract_tx();
    // tx.verify(|_| {
    //     Some(TxOut {
    //         value: 0,
    //         script_pubkey: vault_outpoint.,
    //     })
    // })
    // .expect("failed to verify transaction");

    Ok(tx)
}

fn sign_psbt_taproot(
    signing_keypair: &secp256k1::KeyPair,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    hash_ty: TapSighashType,
    secp: &Secp256k1<secp256k1::All>,
) {
    let keypair = match leaf_hash {
        None => signing_keypair
            .tap_tweak(secp, psbt_input.tap_merkle_root)
            .to_inner(),
        Some(_) => signing_keypair.clone(), // no tweak for script spend
    };

    let sig = secp.sign_schnorr(&hash.into(), &keypair);

    let final_signature = taproot::Signature { sig, hash_ty };

    if let Some(lh) = leaf_hash {
        psbt_input
            .tap_script_sigs
            .insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}

fn bn2vch(v: i64) -> Vec<u8> {
    let mut arr: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let n_bytes = write_scriptint(&mut arr, v);
    arr[..n_bytes].to_vec()
}

#[test]
fn test_bn2vch() {
    assert!(bn2vch(0).len() == 0, "Should encode 0 as ''");
    assert!(bn2vch(1) == vec![1], "Should encode 1 as 'x01'");
    assert!(bn2vch(-1) == vec![129], "Should encode -1 as 'x81'");
    assert!(bn2vch(128) == vec![128, 0], "Should encode 128 as 'x8000'");
    assert!(
        bn2vch(-128) == vec![128, 128],
        "Should encode -128 as 'x8080'"
    );
}
