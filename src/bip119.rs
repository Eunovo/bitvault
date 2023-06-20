use bitcoin::{Transaction, TxOut};
use secp256k1::hashes::{sha256, Hash};

fn ser_compact_size(l: u64) -> Vec<u8> {
    let mut r = vec![];
    if l < 253 {
        // Serialize as unsigned char
        r.push(l as u8);
    } else if l < 0x10000 {
        // Serialize as unsigned char 253 followed by unsigned 2 byte integer (little endian)
        r.push(253);
        r.extend_from_slice(&(l as u16).to_le_bytes());
    } else if l < 0x100000000 {
        // Serialize as unsigned char 254 followed by unsigned 4 byte integer (little endian)
        r.push(254);
        r.extend_from_slice(&(l as u32).to_le_bytes());
    } else {
        // Serialize as unsigned char 255 followed by unsigned 8 byte integer (little endian)
        r.push(255);
        r.extend_from_slice(&l.to_le_bytes());
    }
    return r;
}

#[test]
fn test_ser_compact_size() {

}

fn ser_string(s: &str) -> Vec<u8> {
    let mut v = ser_compact_size(s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    return v;
}

#[test]
fn test_ser_string() {
    
}

fn ser_tx_out(tx_out: &TxOut) -> Vec<u8> {
    let mut r = vec![];
    r.extend_from_slice(&(tx_out.value as i64).to_le_bytes());
    r.extend_from_slice(&ser_string(&tx_out.script_pubkey.to_hex_string()));
    r
}

#[test]
fn test_ser_tx_out() {
    
}

fn hash(data: &Vec<u8>) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

pub fn get_standard_template_hash(transaction: &Transaction, input_index: u32) -> [u8; 32] {
    let mut r = vec![];
    r.extend_from_slice(&transaction.version.to_le_bytes());
    r.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());

    if transaction.input.iter().any(|input| input.script_sig.len() > 0) {
        let script_sigs = transaction.input.iter()
            .map(|input| input.script_sig.clone());
        let mut script_sigs_serialized = vec![];
        for script_sig in script_sigs {
            script_sigs_serialized.extend_from_slice(&ser_string(&script_sig.to_hex_string()));
        }
        r.extend_from_slice(&hash(&script_sigs_serialized));
    }

    r.extend_from_slice(&(transaction.input.len() as u32).to_le_bytes());
    let input_n_sequences = transaction.input.iter()
        .map(|input| input.sequence.to_consensus_u32().to_le_bytes())
        .flatten()
        .collect::<Vec<_>>();
    r.extend_from_slice(&hash(&input_n_sequences));

    r.extend_from_slice(&(transaction.output.len() as u32).to_le_bytes());
    let output_serialized = transaction.output.iter()
        .map(|output| ser_tx_out(output))
        .flatten()
        .collect::<Vec<_>>();
    r.extend_from_slice(&hash(&output_serialized));
    
    r.extend_from_slice(&input_index.to_le_bytes());

    hash(&r)
}

#[test]
fn test_get_standard_template_hash() {
    
}
