// #[post("/login", params = "<login>")]
// pub async fn login(state: &State<ServerState>, login: Form<Login>) -> Result<Json<UserAccount>, Status> {
//     let mut ldap = state.ldap.lock().await;
//     let user = fetch_user(&mut ldap, &login.username, &login.password).await;
//     match user {
//         Ok(user) => Ok(Json(user)),
//         Err(_) => Err(Status::Unauthorized),
//     }
// }