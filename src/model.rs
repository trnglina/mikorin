use chrono::{DateTime, Utc};
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
    pub groups: Vec<Group>,
}

#[derive(Debug, Serialize)]
pub struct Token {
    pub token: String,
    pub user_id: i64,
    pub expires: DateTime<Utc>,
}
