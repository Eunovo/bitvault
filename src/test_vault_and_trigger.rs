use bitcoin::{
    amount::Amount,
    bech32::ToBase32,
    consensus::encode,
    hashes::Hash,
    locktime::absolute::LockTime,
    psbt::{self, Input, Psbt, PsbtSighashType},
    Address, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use secp256k1::{rand::rngs::OsRng, Secp256k1};

use crate::{
    bitcoin::{
        connect_to_bitcoind, generate_to_address, get_new_address, import_privkey, list_unspent,
    },
    commands::{create_trigger::create_trigger_tranx, create_vault::create_vault_script},
};
use std::collections::BTreeMap;

#[test]
fn test_vault_and_trigger() {
    let client = connect_to_bitcoind();
    let secp = Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut OsRng);
    let pub_key = PublicKey::new(pk);
    let pay_script = ScriptBuf::new_v0_p2wpkh(&pub_key.wpubkey_hash().unwrap());

    import_privkey(
        &client,
        &String::from_utf8(sk.secret_bytes().to_vec()).expect("Should extract string key"),
    )
    .expect("Should import private key");
    let address = Address::from_script(&pay_script, bitcoin::Network::Regtest)
        .unwrap()
        .to_string();
    generate_to_address(&client, &address);
    let utxos = list_unspent(&client, &address);
    let utxo = &utxos[0];

    let vault = create_vault_script();
    let utxo_amount_in_sats = Amount::from_btc(utxo.amount).unwrap().to_sat();
    let amount = utxo_amount_in_sats - 200; // pay fee
    let vault_tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(
                Txid::from_raw_hash(Hash::from_slice(utxo.txid.as_bytes()).unwrap()),
                utxo.vout,
            ),
            witness: Witness::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
        }],
        output: vec![TxOut {
            value: amount,
            script_pubkey: vault.vault_script,
        }],
    };
    let prev_out = TxOut {
        value: utxo_amount_in_sats,
        script_pubkey: ScriptBuf::from_hex(&utxo.scriptPubKey).unwrap(),
    };
    let mut vault_psbt = Psbt::from_unsigned_tx(vault_tx).unwrap();
    vault_psbt.inputs = vec![Input {
        witness_utxo: Some(prev_out),
        redeem_script: Some(pay_script),
        ..Default::default()
    }];
    let mut map = BTreeMap::new();
    map.insert(pub_key, PrivateKey::new(sk, bitcoin::Network::Regtest));
    vault_psbt.sign(&map, &secp).unwrap();
    finalize_psbt(vault_psbt, &pub_key);

    let tx = vault_psbt.extract_tx();
    tx.verify(|_| Some(prev_out))
        .expect("failed to verify transaction");

    let hex = encode::serialize_hex(&tx);

    // send transaction here

    let vault_outpoint = OutPoint::new(tx.txid(), 0);
    let trigger_tx =
        create_trigger_tranx(&vault, amount, &vault_outpoint).expect("Should create trigger tx");
    let trigger_tx_hex = encode::serialize_hex(&trigger_tx);

    // send transaction here
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
