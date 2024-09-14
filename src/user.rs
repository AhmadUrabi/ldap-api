#![allow(dead_code, non_snake_case)]

use std::collections::{HashMap, HashSet};

use base64::Engine;
use ldap3::{Ldap, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use ldap3::Mod;


#[derive(Serialize, Deserialize, Debug)]
pub struct UserParams {
    pub cn: String,
    pub givenName: String,
    pub sn: String,
    pub displayName: String,
    pub userPrincipalName: String,
    pub sAMAccountName: String,
    pub mail: String,
    pub password: String,
}

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

impl UserAccount {
    pub fn default() -> Self {
        UserAccount {
            sAMAccountName: None,
            sn: None,
            badPasswordTime: None,
            uSNChanged: None,
            objectClass: None,
            logonCount: None,
            homeDirectory: None,
            accountExpires: None,
            lastLogonTimestamp: None,
            lastLogoff: None,
            distinguishedName: None,
            countryCode: None,
            objectCategory: None,
            cn: None,
            codePage: None,
            memberOf: None,
            instanceType: None,
            name: None,
            givenName: None,
            sAMAccountType: None,
            userPrincipalName: None,
            whenChanged: None,
            pwdLastSet: None,
            badPwdCount: None,
            lastLogon: None,
            whenCreated: None,
            displayName: None,
            homeDrive: None,
            userAccountControl: None,
            primaryGroupID: None,
            uSNCreated: None,
            dSCorePropagationData: None,
        }
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

    pub async fn create_new_user(ldap: &mut Ldap, user: UserParams) -> Result<UserAccount, ldap3::LdapError> {
        let binding = format!("CN={},{}", user.cn, std::env::var("BASE_DN").unwrap()).to_owned();
        let new_user_dn = binding.as_str();
        let quoted_b64_password = format!("'{}'", user.password);
    
        let new_password_utf16: Vec<u16> = quoted_b64_password.encode_utf16().collect();
        let new_password_bytes: Vec<u8> = new_password_utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();
        let b64_password = base64::engine::general_purpose::STANDARD.encode(&new_password_bytes);
        
        let mut password_utf16: HashSet<&[u8]> = HashSet::new();
        password_utf16.insert(&b64_password.as_bytes());
    
        let new_user_attrs = vec![
            ("objectClass", ["top", "person", "organizationalPerson", "user"].iter().cloned().collect::<HashSet<_>>()), // Object Class
            ("cn", [user.cn.as_str()].iter().cloned().collect::<HashSet<_>>()), // Common Name
            ("givenName", [user.givenName.as_str()].iter().cloned().collect::<HashSet<_>>()), // First Name
            ("sn", [user.sn.as_str()].iter().cloned().collect::<HashSet<_>>()), // Surname
            ("displayName", [user.givenName.as_str()].iter().cloned().collect::<HashSet<_>>()), // Display Name
            ("userPrincipalName", [user.userPrincipalName.as_str()].iter().cloned().collect::<HashSet<_>>()), // User Logon Name
            ("sAMAccountName", [user.sAMAccountName.as_str()].iter().cloned().collect::<HashSet<_>>()), // User Logon Name
            ("mail", [user.mail.as_str()].iter().cloned().collect::<HashSet<_>>()), // Internal Mail
        ];
        let res = ldap.add(new_user_dn, new_user_attrs).await?;
    
        println!("Add result: {:?}", res);
    
        Self::set_password(ldap, new_user_dn, &user.password).await?;
        Self::update_user_account_control(ldap, new_user_dn, 66048).await?;
    
        match Self::fetch_user(ldap, new_user_dn).await {
            Some(user) => Ok(user),
            None => Err(ldap3::LdapError::EndOfStream),
        }
    }
    
    pub async fn fetch_user(ldap: &mut Ldap, dn: &str) -> Option<UserAccount> {
        let (rs, _res) = ldap.search(
            dn,
            ldap3::Scope::Base,
            "(objectClass=user)",
            vec!["*", "+"],
        ).await.ok()?.success().ok()?;  // Get the search result
       
        let entry = rs.into_iter().next()?;
    
        let entry = ldap3::SearchEntry::construct(entry);
    
        Some(entry.attrs.into())
    }
    
    async fn set_password(conn: &mut ldap3::Ldap, user_dn: &str, new_password: &str) -> Result<(), ldap3::LdapError> {
        // Encode the password
        let attr_name = String::from("unicodePwd").into_bytes();
        let values: Vec<u8> = format!("\"{}\"",new_password).encode_utf16().flat_map(|v|v.to_le_bytes()).collect();
        let mut passwd = HashSet::new();
        passwd.insert(values);
        let mods = vec![
            Mod::Replace(attr_name,passwd)
        ];
        let result = conn.modify(&user_dn, mods).await.unwrap();
        println!("Set password result: {:?}", result);
        Ok(())
    }
    
    
    
    async fn update_user_account_control(conn: &mut ldap3::Ldap, user_dn: &str, flag: u32) -> Result<(), ldap3::LdapError> {
        // First, get the current userAccountControl value
        let res = conn.modify(
            user_dn,
            vec![
                ldap3::Mod::Replace("userAccountControl", HashSet::from([flag.to_string().as_str()])),
            ],
        ).await;
        println!("Update user account control result: {:?}", res);
        Ok(())
    }    
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

