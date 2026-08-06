use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::models::ErrorResponse;

pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid admin bearer token")
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}
