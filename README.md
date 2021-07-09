# auth0_rs

Simple Auth0 access token validation package.

## Usage

Use `Auth0::new(JWKS_URL)` to initialize your an `Auth0` instance.
Then pass in your access token to the function `auth0.validate_token(YOUR_TOKEN)`.
This function returns a `serde_json::Value` type object as `Claims` if the validation is successful;
otherwise returns an error.

Example:
```rust
let auth0 = Auth0::new("YOUR_AUTH0_URL/.well_known/jwks.json").unwrap();
let token = "YOUR_ACCESS_TOKEN";
let res = auth0.validate_token(token);
assert_eq!(res.is_ok(), true);
let claims = res.unwrap();
assert_eq!(claims.as_object().unwrap().get("aud").unwrap(), "https://github.com/digizeph/auth0_rs");
```
