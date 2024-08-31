#![allow(dead_code, non_snake_case)]

use std::collections::{HashMap, HashSet};

use ldap3::LdapConn;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct UserAccount {
    pub sAMAccountName: Option<Vec<String>>,
    pub sn: Option<Vec<String>>,
    pub badPasswordTime: Option<Vec<String>>,
    pub uSNChanged: Option<Vec<String>>,
    pub objectClass: Option<Vec<String>>,
    pub logonCount: Option<Vec<String>>,
    pub homeDirectory: Option<Vec<String>>,
    pub accountExpires: Option<Vec<String>>,
    pub lastLogonTimestamp: Option<Vec<String>>,
    pub lastLogoff: Option<Vec<String>>,
    pub distinguishedName: Option<Vec<String>>,
    pub countryCode: Option<Vec<String>>,
    pub objectCategory: Option<Vec<String>>,
    pub cn: Option<Vec<String>>,
    pub codePage: Option<Vec<String>>,
    pub memberOf: Option<Vec<String>>,
    pub instanceType: Option<Vec<String>>,
    pub name: Option<Vec<String>>,
    pub givenName: Option<Vec<String>>,
    pub sAMAccountType: Option<Vec<String>>,
    pub userPrincipalName: Option<Vec<String>>,
    pub whenChanged: Option<Vec<String>>,
    pub pwdLastSet: Option<Vec<String>>,
    pub badPwdCount: Option<Vec<String>>,
    pub lastLogon: Option<Vec<String>>,
    pub whenCreated: Option<Vec<String>>,
    pub displayName: Option<Vec<String>>,
    pub homeDrive: Option<Vec<String>>,
    pub userAccountControl: Option<Vec<String>>,
    pub primaryGroupID: Option<Vec<String>>,
    pub uSNCreated: Option<Vec<String>>,
    pub dSCorePropagationData: Option<Vec<String>>,
}

impl From<HashMap<String, Vec<String>>> for UserAccount {
    fn from(attrs: HashMap<String, Vec<String>>) -> Self {
        Self {
            sAMAccountName: attrs.get("sAMAccountName").cloned(),
            sn: attrs.get("sn").cloned(),
            badPasswordTime: attrs.get("badPasswordTime").cloned(),
            uSNChanged: attrs.get("uSNChanged").cloned(),
            objectClass: attrs.get("objectClass").cloned(),
            logonCount: attrs.get("logonCount").cloned(),
            homeDirectory: attrs.get("homeDirectory").cloned(),
            accountExpires: attrs.get("accountExpires").cloned(),
            lastLogonTimestamp: attrs.get("lastLogonTimestamp").cloned(),
            lastLogoff: attrs.get("lastLogoff").cloned(),
            distinguishedName: attrs.get("distinguishedName").cloned(),
            countryCode: attrs.get("countryCode").cloned(),
            objectCategory: attrs.get("objectCategory").cloned(),
            cn: attrs.get("cn").cloned(),
            codePage: attrs.get("codePage").cloned(),
            memberOf: attrs.get("memberOf").cloned(),
            instanceType: attrs.get("instanceType").cloned(),
            name: attrs.get("name").cloned(),
            givenName: attrs.get("givenName").cloned(),
            sAMAccountType: attrs.get("sAMAccountType").cloned(),
            userPrincipalName: attrs.get("userPrincipalName").cloned(),
            whenChanged: attrs.get("whenChanged").cloned(),
            pwdLastSet: attrs.get("pwdLastSet").cloned(),
            badPwdCount: attrs.get("badPwdCount").cloned(),
            lastLogon: attrs.get("lastLogon").cloned(),
            whenCreated: attrs.get("whenCreated").cloned(),
            displayName: attrs.get("displayName").cloned(),
            homeDrive: attrs.get("homeDrive").cloned(),
            userAccountControl: attrs.get("userAccountControl").cloned(),
            primaryGroupID: attrs.get("primaryGroupID").cloned(),
            uSNCreated: attrs.get("uSNCreated").cloned(),
            dSCorePropagationData: attrs.get("dSCorePropagationData").cloned(),
        }
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

    let new_password = "";

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