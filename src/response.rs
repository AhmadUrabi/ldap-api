
use rocket::response::{Responder, Result};
use rocket::http::Status;
use rocket::serde::json::Json;
use serde::Serialize;
use rocket::Request;

#[derive(Serialize)]
pub struct ApiResponseInner<T> {
    pub message: String,
    pub status: u16,
    pub data: Option<T>,
}

pub struct ApiResponse<T> {
    inner: ApiResponseInner<T>,
    status: Status,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn new(message: String, status: Status, data: Option<T>) -> Self {
        ApiResponse {
            inner: ApiResponseInner {
                message,
                status: status.code,
                data,
            },
            status,
        }
    }
}

impl<'r, T: Serialize> Responder<'r, 'static> for ApiResponse<T> {
    fn respond_to(self, _: &'r Request<'_>) -> Result<'static> {
        let json = Json(self.inner);

        let mut buffer = Vec::new();
        let serializer = &mut serde_json::Serializer::new(&mut buffer);
        json.serialize(serializer).unwrap();
        let json_string = String::from_utf8(buffer).unwrap();
        
        rocket::response::Response::build()
        .header(rocket::http::ContentType::JSON)
        .status(self.status)
        .sized_body(json_string.len(), std::io::Cursor::new(json_string))
        .ok()
    }
}
