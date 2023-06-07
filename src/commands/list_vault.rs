use crate::db::VaultTable;

pub fn list_vault(db: VaultTable) {
    match db.read(None) {
        Ok(v) => {
            println!("Found {0} results", v.len());
            for vault in v {
                println!("{0}: {1}", vault.0, vault.1);
            }
        },
        Err(e) => eprintln!("Failed to list vaults: {0}", e.to_string())
    };
}
