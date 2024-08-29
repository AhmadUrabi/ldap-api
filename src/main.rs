use std::collections::HashSet;

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};

use dotenv::dotenv;

fn main() -> Result<(), String> {

    dotenv().ok();

    // Define the LDAP server address
    let ldap_server = std::env::var("LDAP_SERVER").unwrap();

    // Define the domain, username, and password
    let username = std::env::var("LOGIN_USERNAME").unwrap();
    let password = std::env::var("LOGIN_PASSWORD").unwrap();

    // Establish a connection with the LDAP server
    let ldap_conn_settings = LdapConnSettings::new().set_starttls(true);
    let mut ldap = LdapConn::with_settings(ldap_conn_settings, ldap_server.as_str()).unwrap();

    // Bind to the server (authenticate)
    ldap.simple_bind(username.as_str(), password.as_str()).unwrap().success().unwrap();

    fetch_all_users(&mut ldap);   
    

    Ok(())
}

pub fn fetch_all_users(ldap: &mut LdapConn) {
    let base_dn = "OU=HQ,DC=urabi,DC=net";
    // Perform a search
    let (rs, _res) = ldap.search(
        base_dn,
        Scope::Subtree,
        "(objectClass=user)",
        vec!["*", "+"],
    ).unwrap().success().unwrap();

    // Iterate through search results and print them
    for entry in rs {
        let entry = SearchEntry::construct(entry);
        println!("CN: {:?}", entry.attrs);
    }
}

pub fn create_user(ldap: &mut LdapConn) {
    let new_user_dn = "CN=TEST LDAP,OU=HQ,DC=urabi,DC=net";

    let new_user_attrs = vec![
        ("objectClass", ["top", "person", "organizationalPerson", "user"].iter().cloned().collect::<HashSet<_>>()),
        ("cn", ["TEST LDAP"].iter().cloned().collect::<HashSet<_>>()),
        ("givenName", ["TEST"].iter().cloned().collect::<HashSet<_>>()),
        ("sn", ["LDAP"].iter().cloned().collect::<HashSet<_>>()),
        ("displayName", ["TEST LDAP"].iter().cloned().collect::<HashSet<_>>()),
        ("userPrincipalName", ["TESTDLAP@urabi.net"].iter().cloned().collect::<HashSet<_>>()),
        ("sAMAccountName", ["TESTLDAP"].iter().cloned().collect::<HashSet<_>>()),
        ("mail", ["TESTLDAP@urabi.net"].iter().cloned().collect::<HashSet<_>>()),
        // Add more attributes as necessary
    ];

    let res = ldap.add(new_user_dn, new_user_attrs).ok();

    println!("Add result: {:?}", res);

    ***REMOVED***

    // Convert the password to UTF-16LE and wrap in quotes
    let mut password_utf16: HashSet<&str> = HashSet::new();
    password_utf16.insert(&new_password);

    // Set the password using the unicodePwd attribute
    let modify_password = ldap.modify(
        new_user_dn,
        vec![
            ldap3::Mod::Replace("unicodePwd", password_utf16),
        ],
    ).ok();

    println!("Password set successfully {:?}", modify_password);

    // Optionally, enable the account
    let enable_account = ldap.modify(
        new_user_dn,
        vec![
            ldap3::Mod::Replace("userAccountControl", HashSet::from(["66048"])),  // 512 = Normal account
        ],
    ).ok();

    println!("User account enabled successfully, {:?}", enable_account);

    
}