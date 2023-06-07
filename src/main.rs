mod bitcoin;
mod commands;
mod db;

use crate::bitcoin::connect_to_bitcoind;
use commands::{create_vault::create_vault, list_vault::list_vault};
use db::VaultTable;
use std::{env, process};

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
    let (method, args) = parse_args(env::args().collect());
    let _client = connect_to_bitcoind();
    let db = db::DB::connect().expect("Should start Sqlite");
    let vault_table = VaultTable::new(db);
 
    match method.as_str() {
        "create-vault" => create_vault(vault_table, &args[0]),
        "list-vault" => list_vault(vault_table),
        _ => eprintln!("\"{method}\" not supported"),
    }
}
