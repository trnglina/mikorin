use serde::{Deserialize, Serialize};
use sqlx::postgres::{self, PgTypeInfo};

#[derive(Eq, PartialEq, Clone, Copy, Hash, Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "Permission")]
#[allow(non_camel_case_types)]
pub enum Permission {
    #[sqlx(rename = "groups.create")]
    #[serde(rename = "groups.create")]
    Groups_Create,
    #[sqlx(rename = "groups.delete")]
    #[serde(rename = "groups.delete")]
    Groups_Delete,
    #[sqlx(rename = "groups.edit")]
    #[serde(rename = "groups.edit")]
    Groups_Edit,
    #[sqlx(rename = "users.group_id.edit")]
    #[serde(rename = "users.group_id.edit")]
    Users_GroupId_Edit,
}

impl postgres::PgHasArrayType for Permission {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("_Permission")
    }
}

#[derive(Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize, sqlx::Decode)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct PermissionVec(Vec<Permission>);

impl sqlx::Type<sqlx::Postgres> for PermissionVec {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("_Permission")
    }
}

impl From<Vec<Permission>> for PermissionVec {
    fn from(vec: Vec<Permission>) -> Self {
        Self(vec)
    }
}

impl From<PermissionVec> for Vec<Permission> {
    fn from(PermissionVec(vec): PermissionVec) -> Self {
        vec
    }
}

#[derive(Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub permissions: PermissionVec,
}

#[derive(Eq, PartialEq, Clone, Hash, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub name: Option<String>,
    pub group_id: i64,
}
