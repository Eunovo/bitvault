use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::Network::Regtest;
use bitcoin::{script, Address, ScriptBuf, Sequence};
use jsonrpc::simple_http::SimpleHttpTransport;
use jsonrpc::Client;
use secp256k1::hashes::sha256;
use secp256k1::{KeyPair, rand, Secp256k1};
use serde::{Deserialize, Serialize};
use std::{env, process};

#[derive(Serialize, Deserialize, Debug)]
struct SampleRequest {
    message: String,
}

fn connect_to_bitcoind() -> Client {
    let t = SimpleHttpTransport::builder()
        .url(&"localhost:18443")
        .expect("Failed to connect to bitcoind")
        .auth(&"bitcoinrpc", Some(&"zeddicus"))
        .build();

    let result = Client::with_transport(t);
    return result;
}

fn serialize<T>(data: &T) -> Box<serde_json::value::RawValue>
where
    T: ?Sized + Serialize,
{
    serde_json::value::to_raw_value(&data).expect("Failed to serialize request")
}

fn send_json_request<R: for<'a> serde::de::Deserialize<'a>>(
    client: &Client,
    method: &str,
    params: &[Box<serde_json::value::RawValue>],
) -> R {
    let request = client.build_request(method, &params);
    let response = client
        .send_request(request)
        .expect("Failed to send request");
    response.result::<R>().expect("Expected result")
}

fn echo_bitcond(client: &Client) -> bool {
    let sample = SampleRequest {
        message: "Hello World".to_string(),
    };
    let result: Vec<SampleRequest> = send_json_request(client, "echojson", &[serialize(&sample)]);
    result[0].message == "Hello World"
}

#[test]
fn test_connect_to_bitcoind() {
    let client = connect_to_bitcoind();
    assert!(echo_bitcond(&client) == true);
}

#[derive(Serialize, Deserialize, Debug)]
struct BitcoindError {
    code: i32,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ImportDescriptor {
    desc: String,
    label: String,
    timestamp: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ImportDescriptorResponse {
    success: bool,
    error: Option<BitcoindError>,
}

#[derive(Serialize, Deserialize, Debug)]
struct DescriptorInfo {
    checksum: String,
}

fn import_privkey(client: &Client) -> Result<bool, Box<dyn std::error::Error>> {
    let privkey = "cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr";
    let desc = format!("pk({privkey})");
    let descriptor_info: DescriptorInfo =
        send_json_request(client, "getdescriptorinfo", &[serialize(&desc)]);
    let checksum = descriptor_info.checksum;
    let import_desc_req = [ImportDescriptor {
        desc: format!("{desc}#{checksum}"),
        label: "bitvault".to_string(),
        timestamp: 0,
    }];
    let response: Vec<ImportDescriptorResponse> =
        send_json_request(client, "importdescriptors", &[serialize(&import_desc_req)]);
    if response[0].success {
        return Ok(true);
    }

    match &response[0].error {
        Some(v) => return Err(v.message.clone().into()),
        None => {
            return Err(Box::from(
                "Could not import private key: an unexpected error occured",
            ))
        }
    };
}

#[test]
fn test_import_privkey() {
    let client = connect_to_bitcoind();
    match import_privkey(&client) {
        Ok(_) => return,
        Err(e) => panic!("{}", e),
    };
}

fn get_new_address(client: &Client) -> String {
    let address: String = send_json_request(
        client,
        "getnewaddress",
        &[serialize(&"bitvault".to_string())],
    );
    address
}

fn generate_to_address(client: &Client, address: &String) {
    send_json_request::<Vec<String>>(
        client,
        "generatetoaddress",
        &[serialize(&101), serialize(address)],
    );
}

#[derive(Serialize, Deserialize, Debug)]
struct ListUnspentResponse {
    txid: String,
    vout: i32,
    address: String,
    label: String,
    scriptPubKey: String,
    amount: f32,
    confirmations: i32,
    redeemScript: Option<String>,
    witnessScript: Option<String>,
    spendable: bool,
    solvable: bool,
    reused: Option<bool>,
    desc: Option<String>,
    safe: bool,
}

fn list_unspent(client: &Client, address: &String) -> Vec<ListUnspentResponse> {
    send_json_request::<Vec<ListUnspentResponse>>(
        client,
        "listunspent",
        &[serialize(&1), serialize(&9999999), serialize(&[address])],
    )
}

#[test]
fn test_generate_and_fetch_coins() {
    let client = connect_to_bitcoind();
    match import_privkey(&client) {
        Ok(_) => {
            let address = get_new_address(&client);
            generate_to_address(&client, &address);
            let coins = list_unspent(&client, &address);
            assert!(
                coins.len() > 0,
                "Expected to have at least one matureed coin"
            );
            assert!(coins[0].spendable == true, "Expected coin to be spendable");
        }
        Err(e) => panic!("{}", e),
    };
}

fn tag_engine(tag_name: &str) -> sha256::HashEngine {
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine
}

fn create_vault_script() -> ScriptBuf {
    let op_vault = 0xbb;
    let op_vault_recover = 0xbc;
    let op_ctv = 0xb3;

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
        .push_opcode(op_vault_recover.into())
        .into_script();

    let spend_delay = 10;
    // let vault_script_str = format!("{OP_CSV}{OP_DROP}{OP_CTV}");
    let vault_script = script::Builder::new()
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(op_ctv.into())
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
        .push_opcode(op_vault.into())
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(1, recovery_script.clone())
        .expect("Should add recovery script")
        .add_leaf(1, trigger_script.clone())
        .expect("Should add trigger script")
        .finalize(&secp, recovery_internal_key)
        .expect("Should be finalizable");

    ScriptBuf::new_v1_p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
    )
}

fn create_vault() {
    let vault_script = create_vault_script();
    let address = Address::from_script(&vault_script, Regtest)
        .expect("Should create address");
    println!("New Vault Address: {address}");
}

#[test]
fn test_create_vault() {
    let vault_script = create_vault_script();
    let address = Address::from_script(&vault_script, Regtest);
    assert!(address.is_ok(), "Should be okay");
}

// Exits with error
fn show_usage() {
    eprintln!("Usage:");
    eprintln!("bitvault [--conf conf_path] <command> [<param 1> <param 2> ...]");
    process::exit(1);
}

// Returns (Maybe(special conf file), Raw, Method name, Maybe(List of parameters))
fn parse_args(mut args: Vec<String>) -> (String, Vec<String>) {
    if args.len() < 2 {
        eprintln!("Not enough arguments.");
        show_usage();
    }

    args.remove(0); // Program name

    let mut args = args.into_iter();

    loop {
        match args.next().as_deref() {
            Some("--conf") => {
                if args.len() < 2 {
                    eprintln!("Not enough arguments.");
                    show_usage();
                }

                // TODO conf file
                // conf_file = Some(PathBuf::from(args.next().expect("Just checked")));
            }
            Some(method) => return (method.to_owned(), args.collect()),
            None => {
                // Should never happen...
                eprintln!("Not enough arguments.");
                show_usage();
            }
        }
    }
}

fn main() {
    let (method, _args) = parse_args(env::args().collect());
    let _client = connect_to_bitcoind();
    match method.as_str() {
        "create-vault" => create_vault(),
        _ => eprintln!("\"{method}\" not supported")
    }
}
