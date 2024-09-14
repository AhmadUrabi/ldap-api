#[macro_use] extern crate rocket;
use std::{sync::Arc, vec};

use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings};

use dotenv::dotenv;
use response::ApiResponse;
use rocket::{serde::json::Json, State};
use user::{UserAccount, UserParams};

pub mod auth;
pub mod user;
pub mod response;

pub struct ServerState {
    ldap: Arc<rocket::tokio::sync::Mutex<Ldap>>,
}

#[get("/users")]
pub async fn get_all_users(state: &State<ServerState>) -> ApiResponse<Vec<UserAccount>> {
    let mut ldap = state.ldap.lock().await;
    let users = UserAccount::fetch_all_users(&mut ldap).await;
    ApiResponse::new("Success".to_string(), rocket::http::Status::Ok, Some(users))
}

#[post("/users", format = "json", data = "<user>")]
pub async fn create_user(user: Json<UserParams>, state: &State<ServerState>) -> ApiResponse<UserAccount> {
    let mut ldap = state.ldap.lock().await;
    let user_data = user.into_inner();
    let new_user = UserAccount::create_new_user(&mut ldap, user_data).await;

    match new_user {
        Ok(user) => ApiResponse::new("Created".to_string(), rocket::http::Status::Created, Some(user)),
        Err(_) => ApiResponse::new("Error Creating User".to_string(), rocket::http::Status::InternalServerError, None),
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();

    // Define the LDAP server address
    let ldap_server = std::env::var("LDAP_SERVER").unwrap();

    // Define the domain, username, and password
    let username = std::env::var("LOGIN_USERNAME").unwrap();
    let password = std::env::var("LOGIN_PASSWORD").unwrap();

    // Establish a connection with the LDAP server
    let ldap_conn_settings = LdapConnSettings::new().set_starttls(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(ldap_conn_settings, ldap_server.as_str()).await.unwrap();

    drive!(conn);

    ldap.simple_bind(username.as_str(), password.as_str()).await.unwrap().success().unwrap();

    let server_state = ServerState {
        ldap: Arc::new(rocket::tokio::sync::Mutex::new(ldap)),
    };

    rocket::build().manage(server_state).register("/", catchers![not_found]).mount("/", routes![get_all_users, create_user])
}

#[catch(404)]
fn not_found(req: &rocket::Request) -> ApiResponse<()> {
    ApiResponse::new(format!("{} Not Found", req.uri()), rocket::http::Status::NotFound, None)
}