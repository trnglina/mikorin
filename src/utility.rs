use axum::http::StatusCode;
use serde::{Deserialize, Deserializer};

macro_rules! internal_error {
    ($err:expr) => {{
        tracing::error!("{:?}", $err);
        StatusCode::INTERNAL_SERVER_ERROR
    }};
}

// https://github.com/serde-rs/serde/issues/984#issuecomment-314143738
pub fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

pub type ApiResult<T> = Result<T, StatusCode>;

pub mod action {
    use axum::{
        http::{header, StatusCode, Uri},
        response::IntoResponse,
        Json,
    };
    use serde::Serialize;

    use crate::config;

    pub struct List<T>(pub Vec<T>);
    impl<T> IntoResponse for List<T>
    where
        T: Serialize,
    {
        fn into_response(self) -> axum::response::Response {
            let Self(values) = self;
            (Json(values)).into_response()
        }
    }

    pub struct Create<T>(pub T, pub Uri, pub String);
    impl<T> IntoResponse for Create<T>
    where
        T: Serialize,
    {
        fn into_response(self) -> axum::response::Response {
            let Self(value, route_uri, id) = self;
            (
                StatusCode::CREATED,
                [(
                    header::LOCATION,
                    format!("{}/{}/{}", config::BASE_URL, route_uri, id),
                )],
                Json(value),
            )
                .into_response()
        }
    }

    pub struct Show<T>(pub T);
    impl<T> IntoResponse for Show<T>
    where
        T: Serialize,
    {
        fn into_response(self) -> axum::response::Response {
            let Self(value) = self;
            (Json(value)).into_response()
        }
    }

    pub struct Patch;
    impl IntoResponse for Patch {
        fn into_response(self) -> axum::response::Response {
            StatusCode::NO_CONTENT.into_response()
        }
    }

    pub struct Delete;
    impl IntoResponse for Delete {
        fn into_response(self) -> axum::response::Response {
            StatusCode::NO_CONTENT.into_response()
        }
    }
}
