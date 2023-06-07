use sqlite::{open, Connection};

struct Field {
    name: String,
    data_type: String,
}

struct Table {
    name: String,
    fields: Vec<Field>,
}

pub struct DB {
    connection: Connection,
}

impl DB {
    pub fn connect() -> Result<Self, sqlite::Error> {
        let db = DB {
            connection: open("./bitvault.sqlite").unwrap(),
        };
        let tables = vec![Table {
            name: "vaults".to_string(),
            fields: vec![
                Field {
                    name: "name".to_string(),
                    data_type: "TEXT".to_string(),
                },
                Field {
                    name: "address".to_string(),
                    data_type: "TEXT".to_string(),
                },
            ],
        }];

        let query = tables
            .into_iter()
            .map(|table| {
                let fields = table
                    .fields
                    .iter()
                    .map(|field| format!("{0} {1}", field.name, field.data_type))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("CREATE TABLE IF NOT EXISTS {0} ({fields})", table.name)
            })
            .collect::<Vec<_>>()
            .join(";");

        match db.connection.execute(query) {
            Ok(_) => Ok(db),
            Err(e) => Err(e),
        }
    }
}

pub struct VaultTable {
    db: DB,
}

pub struct VaultTableRow(pub String, pub String);

impl VaultTable {
    pub fn new(db: DB) -> Self {
        VaultTable { db }
    }

    pub fn insert(self, row: &VaultTableRow) -> Result<(), sqlite::Error> {
        self.db.connection.execute(format!(
            "INSERT INTO vaults VALUES ('{0}','{1}');",
            row.0, row.1
        ))
    }

    pub fn read(self, name: Option<String>) -> Result<Vec<VaultTableRow>, sqlite::Error> {
        let mut query = "SELECT * FROM vaults".to_string();

        match name {
            Some(n) => query = format!("{query} WHERE name = {n}"),
            None => (),
        }

        let mut rows: Vec<VaultTableRow> = Vec::new();
        let res = self.db.connection.iterate(query, |pairs| {
            let mut iterator = pairs.iter();
            
            loop {
                let name_pair = iterator.next();
                let addr_pair = iterator.next();

                match name_pair {
                    Some((_, name)) => {
                        match addr_pair {
                            Some((_, address)) => rows.push(VaultTableRow(
                                name.unwrap().to_string(),
                                address.unwrap().to_string(),
                            )),
                            None => break
                        }
                    },
                    None => break,
                };
            }

            true
        });

        match res {
            Ok(v) => Ok(rows),
            Err(e) => Err(e),
        }
    }
}
