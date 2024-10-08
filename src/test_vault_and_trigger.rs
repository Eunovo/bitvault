use bitcoin::{
    amount::Amount,
    bech32::ToBase32,
    consensus::encode,
    ecdsa,
    hashes::Hash,
    key,
    locktime::absolute::LockTime,
    psbt::{self, Input, Psbt, PsbtSighashType},
    sighash::{EcdsaSighashType, SighashCache},
    Address, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};

use crate::{
    bitcoin::{
        connect_to_bitcoind, generate_to_address, get_new_address, import_privkey, list_unspent,
        send_raw_transaction, ListUnspentResponse,
    },
    commands::{create_trigger::create_trigger_tranx, create_vault::create_vault_script},
};
use std::collections::BTreeMap;
use std::str::FromStr;

#[test]
fn test_vault_and_trigger() {
    let client = connect_to_bitcoind();
    let secp = Secp256k1::new();

    let priv_key_wif = "cWAGCfVYN8zMBV8XZ7dPf5q1e35FAg76scqXeijwvUvkbVDkp4Gr";
    let priv_key = PrivateKey::from_wif(priv_key_wif).unwrap();
    let pub_key = priv_key.public_key(&secp);
    let redeem_script = ScriptBuf::new_v0_p2wpkh(&pub_key.wpubkey_hash().unwrap());

    import_privkey(&client, &priv_key_wif.to_string()).expect("Should import private key");
    let address = Address::from_script(&redeem_script, bitcoin::Network::Regtest)
        .unwrap()
        .to_string();

    // Generate cash until balance accumulated

    generate_to_address(&client, &address);
    let utxos = list_unspent(&client, &address);

    let vault = create_vault_script();
    let utxo_amount_in_sats = Amount::from_btc(utxos[0].amount).unwrap().to_sat();
    let vault_psbt = finalize_psbt(
        sign_psbt(
            &secp,
            create_psbt(&utxos, utxo_amount_in_sats, &vault.vault_script),
            priv_key,
        ),
        &pub_key,
    )
    .unwrap();
    let tx = vault_psbt.extract_tx();

    let hex = encode::serialize_hex(&tx);
    println!("Hex: {:?}", hex);

    let vault_outpoint = OutPoint::new(tx.txid(), 0);
    let trigger_tx = create_trigger_tranx(&vault, utxo_amount_in_sats - 150, &vault_outpoint)
        .expect("Should create trigger tx");

    let trigger_tx_hex = encode::serialize_hex(&trigger_tx);

    // send transaction here
    println!("Trigger Hex: {:?}", trigger_tx_hex);

    send_raw_transaction(&client, &hex);
    generate_to_address(&client, &address); // To confirm previous transaction
    send_raw_transaction(&client, &trigger_tx_hex);
}

fn create_psbt(utxos: &Vec<ListUnspentResponse>, amount: u64, dest_script: &ScriptBuf) -> Psbt {
    // Map utxos to TxIns
    let utxo = &utxos[0];
    let fee = 150;
    let vault_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::from_str(&format!("{}:{}", utxo.txid, utxo.vout)).unwrap(),
            witness: Witness::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
        }],
        output: vec![TxOut {
            value: amount - fee,
            script_pubkey: dest_script.clone(),
        }],
    };
    let prev_out = TxOut {
        value: amount,
        script_pubkey: ScriptBuf::from_hex(&utxo.scriptPubKey).unwrap(),
    };
    let mut vault_psbt = Psbt::from_unsigned_tx(vault_tx).unwrap();
    vault_psbt.inputs = vec![Input {
        witness_utxo: Some(prev_out.clone()),
        sighash_type: Some(PsbtSighashType::from(EcdsaSighashType::All)),
        ..Default::default()
    }];
    vault_psbt
}

fn sign_psbt(secp: &Secp256k1<secp256k1::All>, mut psbt: Psbt, priv_key: PrivateKey) -> Psbt {
    let pub_key = priv_key.public_key(&secp);
    let unsigned_tx = &psbt.unsigned_tx;
    let hash_ty = psbt.inputs[0]
        .sighash_type
        .unwrap()
        .ecdsa_hash_ty()
        .unwrap();

    let mut sighash = SighashCache::new(unsigned_tx);
    let (message, _) = psbt.sighash_ecdsa(0, &mut sighash).unwrap();

    let sig = secp.sign_ecdsa(
        &message,
        &SecretKey::from_slice(&priv_key.to_bytes()).expect("Should create secret key"),
    );

    let final_signature = ecdsa::Signature { sig, hash_ty };
    psbt.inputs[0].partial_sigs.insert(pub_key, final_signature);

    psbt
}

fn finalize_psbt(mut psbt: Psbt, pub_key: &PublicKey) -> Result<Psbt, Box<dyn std::error::Error>> {
    if psbt.inputs.is_empty() {
        return Err(psbt::SignError::MissingInputUtxo.into());
    }

    let sigs: Vec<_> = psbt.inputs[0].partial_sigs.values().collect();
    let mut script_witness: Witness = Witness::new();
    script_witness.push(&sigs[0].to_vec());
    script_witness.push(pub_key.to_bytes());

    psbt.inputs[0].final_script_witness = Some(script_witness);

    // Clear all the data fields as per the spec.
    psbt.inputs[0].partial_sigs = BTreeMap::new();
    psbt.inputs[0].sighash_type = None;
    psbt.inputs[0].redeem_script = None;
    psbt.inputs[0].witness_script = None;
    psbt.inputs[0].bip32_derivation = BTreeMap::new();

    Ok(psbt)
}
