use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub name: Option<String>,
    pub group_id: i64,
}
