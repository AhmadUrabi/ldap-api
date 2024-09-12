#[macro_use] extern crate rocket;
use std::sync::Arc;

use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use dotenv::dotenv;
use rocket::{serde::json::Json, State};
use user::{create_new_user, UserAccount, UserParams};

pub mod auth;
pub mod user;

pub struct ServerState {
    ldap: Arc<rocket::tokio::sync::Mutex<Ldap>>,
}

#[get("/users")]
pub async fn get_all_users(state: &State<ServerState>) -> Json<Vec<UserAccount>> {
    let mut ldap = state.ldap.lock().await;
    let users = fetch_all_users(&mut ldap).await;   
    Json(users)
}

#[post("/users", format = "json", data = "<user>")]
pub async fn create_user(user: Json<UserParams>, state: &State<ServerState>) -> Json<UserAccount> {
    let mut ldap = state.ldap.lock().await;
    let user_data = user.into_inner();
    let new_user = create_new_user(&mut ldap, user_data).await;

    Json(new_user)
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

    rocket::build().manage(server_state).mount("/", routes![get_all_users, create_user])
}

pub async fn fetch_all_users(ldap: &mut Ldap) -> Vec<UserAccount> {
    let base_dn_string = std::env::var("BASE_DN").unwrap();
    let base_dn = base_dn_string.as_str();
    // Perform a search
    let (rs, _res) = ldap.search(
        base_dn,
        Scope::Subtree,
        "(objectClass=user)",
        vec!["*", "+"],
    ).await.unwrap().success().unwrap();

    let mut res = Vec::new();

    // Iterate through search results and print them
    for entry in rs {
        let entry = SearchEntry::construct(entry);
            let user: UserAccount = entry.attrs.into();
            res.push(user);
        }
    res
}