#[macro_use]
extern crate rocket;
use std::{sync::Arc, vec};

use ldap3::{drive, Ldap, LdapConn, LdapConnAsync, LdapConnSettings, LdapError};

use dotenv::dotenv;
use response::ApiResponse;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::Header,
    serde::json::Json,
    tokio::sync::Mutex,
    Data, Request, Response, State,
};
use user::{UserAccount, UserParams};

pub mod auth;
pub mod response;
pub mod user;

#[derive(Clone)]
pub struct ServerState {
    pub ldap_server: String,
    pub username: String,
    pub password: String,
    pub ldap: Arc<Mutex<Ldap>>,
}

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "POST, GET, PATCH, OPTIONS, DELETE",
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

async fn check_connection(state: &ServerState) -> Result<(), LdapError> {
    let mut ldap = state.ldap.lock().await;
    match ldap.simple_bind(&state.username, &state.password).await {
        Ok(_) => Ok(()),
        Err(_) => {
            *ldap = establish_ldap_connection().await?;
            Ok(())
        }
    }
}

async fn establish_ldap_connection() -> Result<Ldap, LdapError> {
    // Define the LDAP server address
    let ldap_server = std::env::var("LDAP_SERVER").unwrap();

    // Define the domain, username, and password
    let username = std::env::var("LOGIN_USERNAME").unwrap();
    let password = std::env::var("LOGIN_PASSWORD").unwrap();

    // Establish a connection with the LDAP server
    let ldap_conn_settings = LdapConnSettings::new().set_starttls(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(ldap_conn_settings, ldap_server.as_str())
        .await
        .unwrap();

    drive!(conn);

    ldap.simple_bind(username.as_str(), password.as_str())
        .await
        .unwrap()
        .success()
        .unwrap();

    Ok(ldap)
}

#[options("/users")]
pub fn options_users() -> ApiResponse<()> {
    ApiResponse::new(
        "Options for /users".to_string(),
        rocket::http::Status::Ok,
        None,
    )
}

#[options("/users/<uname>")]
pub fn options_users_delete(uname: &str) -> ApiResponse<()> {
    ApiResponse::new(
        "Options for /users".to_string(),
        rocket::http::Status::Ok,
        None,
    )
}

#[get("/users")]
pub async fn get_all_users(state: &State<ServerState>) -> ApiResponse<Vec<UserAccount>> {
    if let Err(_) = check_connection(&state).await {
        loop {
            if let Ok(_) = check_connection(&state).await {
                break;
            }
        }
    }
    let mut ldap = state.ldap.lock().await;
    let users = UserAccount::fetch_all_users(&mut ldap).await;
    ApiResponse::new("Success".to_string(), rocket::http::Status::Ok, Some(users))
}

#[post("/users", format = "json", data = "<user>")]
pub async fn create_user(
    user: Json<UserParams>,
    state: &State<ServerState>,
) -> ApiResponse<UserAccount> {
    let mut ldap = state.ldap.lock().await;
    let user_data = user.into_inner();
    let new_user = UserAccount::create_new_user(&mut ldap, user_data).await;

    match new_user {
        Ok(user) => ApiResponse::new(
            "Created".to_string(),
            rocket::http::Status::Created,
            Some(user),
        ),
        Err(_) => ApiResponse::new(
            "Error Creating User".to_string(),
            rocket::http::Status::InternalServerError,
            None,
        ),
    }
}

#[delete("/users/<uname>")]
pub async fn delete_user(uname: String, state: &State<ServerState>) -> ApiResponse<()> {
    let mut ldap = state.ldap.lock().await;
    let user_dn = UserAccount::get_dn_from_uname(&mut ldap, uname.as_str()).await;
    if user_dn.is_none() {
        return ApiResponse::new(
            "User Not Found".to_string(),
            rocket::http::Status::NotFound,
            None,
        );
    }

    let user_dn = user_dn.unwrap();
    println!("Deleting user: {}", user_dn);

    let res = ldap.delete(user_dn.as_str()).await;
    if res.is_err() {
        return ApiResponse::new(
            "Error Deleting User".to_string(),
            rocket::http::Status::InternalServerError,
            None,
        );
    }
    match res.unwrap().success() {
        Ok(_) => ApiResponse::new("Deleted".to_string(), rocket::http::Status::Ok, None),
        Err(_) => ApiResponse::new(
            "Error Deleting User".to_string(),
            rocket::http::Status::InternalServerError,
            None,
        ),
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();

    let ldap_server = std::env::var("LDAP_SERVER").unwrap();
    let username = std::env::var("LOGIN_USERNAME").unwrap();
    let password = std::env::var("LOGIN_PASSWORD").unwrap();

    let server_state = ServerState {
        ldap_server: ldap_server.clone(),
        username: username.clone(),
        password: password.clone(),
        ldap: Arc::new(Mutex::new(establish_ldap_connection().await.unwrap())),
    };

    rocket::build()
        .manage(server_state)
        .attach(ConnectionFairing)
        .attach(CORS)
        .register("/", catchers![not_found])
        .mount(
            "/",
            routes![
                get_all_users,
                create_user,
                options_users,
                options_users_delete,
                delete_user
            ],
        )
}

#[catch(404)]
fn not_found(req: &rocket::Request) -> ApiResponse<()> {
    ApiResponse::new(
        format!("{} Not Found", req.uri()),
        rocket::http::Status::NotFound,
        None,
    )
}

struct ConnectionFairing;

#[rocket::async_trait]
impl Fairing for ConnectionFairing {
    fn info(&self) -> Info {
        Info {
            name: "LDAP Connection Fairing",
            kind: Kind::Request,
        }
    }

    // Increment the counter for `GET` and `POST` requests.
    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        // get state
        let state = request.guard::<&State<ServerState>>().await.unwrap();

        // check connection
        if let Err(_) = check_connection(&state).await {
            loop {
                if let Ok(_) = check_connection(&state).await {
                    break;
                }
            }
        }
    }
}
