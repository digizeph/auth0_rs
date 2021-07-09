# auth0_rs

Simple Auth0 access token validation package.

## Usage

Use `Auth0::new(JWKS_URL)` to initialize your an `Auth0` instance.
Then pass in your access token to the function `auth0.validate_token(YOUR_TOKEN)`.
This function returns a `serde_json::Value` type object as `Claims` if the validation is successful;
otherwise returns an error.

Example:
```rust
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
```
