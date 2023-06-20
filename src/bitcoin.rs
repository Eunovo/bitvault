use jsonrpc::simple_http::SimpleHttpTransport;
use jsonrpc::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct SampleRequest {
    message: String,
}

pub fn connect_to_bitcoind() -> Client {
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

pub fn send_json_request<R: for<'a> serde::de::Deserialize<'a>>(
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

pub fn import_privkey(client: &Client, privkey: &String) -> Result<bool, Box<dyn std::error::Error>> {
    // let privkey = "cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr";
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
    let privkey = String::from("");
    match import_privkey(&client, &privkey) {
        Ok(_) => return,
        Err(e) => panic!("{}", e),
    };
}

pub fn get_new_address(client: &Client) -> String {
    let address: String = send_json_request(
        client,
        "getnewaddress",
        &[serialize(&"bitvault".to_string())],
    );
    address
}

pub fn generate_to_address(client: &Client, address: &String) {
    send_json_request::<Vec<String>>(
        client,
        "generatetoaddress",
        &[serialize(&101), serialize(address)],
    );
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ListUnspentResponse {
    pub txid: String,
    pub vout: u32,
    address: String,
    label: String,
    pub scriptPubKey: String,
    pub amount: f64,
    confirmations: i32,
    redeemScript: Option<String>,
    witnessScript: Option<String>,
    spendable: bool,
    solvable: bool,
    reused: Option<bool>,
    desc: Option<String>,
    safe: bool,
}

pub fn list_unspent(client: &Client, address: &String) -> Vec<ListUnspentResponse> {
    send_json_request::<Vec<ListUnspentResponse>>(
        client,
        "listunspent",
        &[serialize(&1), serialize(&9999999), serialize(&[address])],
    )
}

#[test]
fn test_generate_and_fetch_coins() {
    let client = connect_to_bitcoind();
    let privkey = String::from("");
    match import_privkey(&client, &privkey) {
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
