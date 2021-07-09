pub mod error;

use std::collections::HashMap;
use serde::Deserialize;
use serde_json::Value;
use jsonwebtoken::{decode_header, decode, DecodingKey, Validation, Algorithm};
use crate::error::{new_error, ErrorKind, Auth0Error};

/// JSON Web Key struct.
///
/// Official documentation of the JSON Web Key format from Auth0:
/// https://auth0.com/docs/tokens/json-web-tokens/json-web-key-set-properties
///
#[derive(Deserialize, Debug, Clone)]
pub struct JsonWebKey {
    /// The specific cryptographic algorithm used with the key.
    pub alg: String,
    /// The family of cryptographic algorithms used with the key.
    pub kty: String,
    /// How the key was meant to be used; sig represents the signature.
    #[serde(alias = "use")]
    pub key_use: String,
    /// The x.509 certificate chain. The first entry in the array is the certificate to use for
    /// token verification; the other certificates can be used to verify this first certificate.
    pub x5c: Option<Vec<String>>,
    /// The modulus for the RSA public key.
    pub n: String,
    /// The exponent for the RSA public key.
    pub e: String,
    /// The unique identifier for the key.
    pub kid: String,
    /// The thumbprint of the x.509 cert (SHA-1 thumbprint).
    pub x5t: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Jwks {
    pub keys: Vec<JsonWebKey>
}

/// Main struct for auth0_rs library
pub struct Auth0 {
    /// HashMap of JSON web keys with key to be `kid` (key ID), and value to be [`JsonWebKey`].
    pub key_map: HashMap<String, JsonWebKey>
}

/// Type rename [`serde_json::Value`] as [`Claims`]
pub type Claims = Value;

impl Auth0 {
    /// Create new Auth0 instance from a JSON web key set (JWKS) str.
    ///
    /// Example:
    /// ```
    /// use auth0_rs::Auth0;
    /// let keys = r#"
    /// {
    ///     "keys":[
    ///         {
    ///           "kty": "RSA",
    ///           "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
    ///           "e": "AQAB",
    ///           "alg": "RS256",
    ///           "kid": "auth0_rs",
    ///           "use": "sig"
    ///         }
    ///     ]
    /// }
    /// "#;
    /// let auth0 = Auth0::new(keys).unwrap();
    /// ```
    ///
    /// The validated token above would reveal the following claims
    /// ```no_run
    /// {
    /// "aud": "https://github.com/digizeph/auth0_rs",
    /// "exp": 32520059430,
    /// "iat": 1625840745,
    /// "iss": "https://jwt.io",
    /// "sub": "first-client",
    /// }
    /// ```
    pub fn new(jwks_str: &str) -> Result<Auth0, Auth0Error>{
        let keys: Jwks = match serde_json::from_str(jwks_str){
            Ok(k) => k,
            Err(_) => {return Err(new_error(ErrorKind::InvalidJwksStr))}
        };
        let key_map = Auth0::jwks_to_keymap(keys);
        Ok( Auth0 { key_map } )
    }

    pub fn jwks_to_keymap(keys: Jwks) -> HashMap<String, JsonWebKey> {
        let mut key_map: HashMap<String, JsonWebKey> = HashMap::new();
        for key in keys.keys {
            key_map.insert(key.kid.clone(), key.clone());
        }
        key_map
    }

    /// Update JSON web keys.
    pub fn update_keys(self: &mut Self, jwks_str: &str) -> Result<(), Auth0Error> {

        let keys: Jwks = match serde_json::from_str(jwks_str){
            Ok(k) => k,
            Err(_) => {return Err(new_error(ErrorKind::InvalidJwksStr))}
        };
        let key_map = Auth0::jwks_to_keymap(keys);
        self.key_map = key_map;
        Ok(())
    }

    /// Validate token and return claims as [`Claims`]
    pub fn validate_token(self: &Self, token: &str) -> Result<Claims, Auth0Error> {
        let key_id = match decode_header(token) {
            Ok(header) => {
                if let Some(kid) = header.kid {
                    kid
                } else {
                    return Err(new_error(ErrorKind::TokenMissingKeyId))
                }
            }
            Err(_) => {
                return Err(new_error(ErrorKind::InvalidToken))
            }
        };

        let key = match self.key_map.get(&key_id) {
            Some(key) => {
                key
            }
            None => {return Err(new_error(ErrorKind::NoMatchKey))}
        };

        match decode::<Value>(
            &token,
            &DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str()),
            &Validation::new(Algorithm::RS256),
        ) {
            Ok(decoded) => Ok(decoded.claims),
            Err(e) => {
                dbg!(e);
                Err(new_error(ErrorKind::InvalidToken))
            },

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation() {
        let keys = r#"
{
    "keys":[
        {
          "kty": "RSA",
          "n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
          "e": "AQAB",
          "alg": "RS256",
          "kid": "auth0_rs",
          "use": "sig"
        }
    ]
}
"#;
        let auth0 = Auth0::new(keys).unwrap();
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImF1dGgwX3JzIn0.eyJpc3MiOiJodHRwczovL2p3dC5pbyIsInN1YiI6ImZpcnN0LWNsaWVudCIsImF1ZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9kaWdpemVwaC9hdXRoMF9ycyIsImlhdCI6MTYyNTg0MDc0NSwiZXhwIjozMjUyMDA1OTQzMH0.TiKL7yBNdqXGAieHKAnfwhFkoKn4_SXf1UObB31vEzYQWVpBadBP7_DkPAehZs2M0AepzQ74iAt1toNYIObtizXYUTFyJQUQcww1cldltnZ4pv4fs7dPxXDfZvuVnne7JHzJmo4D5uHNnKcsIGxotEYNNA2_PfzNmte9kIkwbZc1yRhegVvv7RQ4vR5ZnstURaNBiQJCL10sPUBZ14p7WBKU1agY_9BWThKOO4LdcYnPXJ8rThnZ42Abxkd-wV1DvtEgJKl6QQYZ9t_4fvKRp6cF9WG5u9GoauyMnGV8-9gV3ccYnM6mVeagN1o6Tn2jHIg4e4L3etzfy73ZmY8RcQ";
        let res = auth0.validate_token(token);
        assert_eq!(res.is_ok(), true);
        let claims = res.unwrap();
        dbg!(&claims);
        assert_eq!(claims.as_object().unwrap().get("aud").unwrap(), "https://github.com/digizeph/auth0_rs");
    }
}