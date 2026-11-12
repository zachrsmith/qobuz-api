//! OAuth sign-in through the Qobuz web site: login URL, redirect parsing, and code exchange.
//!
//! The web player sends the user to `/signin/oauth` with an `ext_app_id` and a `redirect_url`.
//! Once the user has signed in, Qobuz redirects back with a `code_autorisation` query parameter,
//! which the player exchanges at `/oauth/callback` together with the bundle's private key. The
//! resulting `user_auth_token` is confirmed with a `user/login` call carrying the token header.

use {serde_json::Value, tracing::info};

use crate::{
    api::{http_client::HttpClient, requests::build_url_with_params, response::parse_response},
    errors::QobuzApiError::{self, AuthenticationError},
};

/// Origin of the Qobuz sign-in pages.
const SIGNIN_ORIGIN: &str = "https://www.qobuz.com";
/// Path of the OAuth sign-in page.
const SIGNIN_PATH: &str = "/signin/oauth";
/// Endpoint that trades an authorisation code for a token.
const CALLBACK_ENDPOINT: &str = "/oauth/callback";
/// Endpoint that confirms a token and describes its user.
const LOGIN_ENDPOINT: &str = "/user/login";
/// Query parameter names Qobuz has used for the authorisation code, most recent first.
const CODE_PARAMS: [&str; 2] = ["code_autorisation", "code"];
/// Response fields that may carry the token.
const TOKEN_FIELDS: [&str; 2] = ["token", "user_auth_token"];
/// Response fields that may carry the user id.
const USER_ID_FIELDS: [&str; 2] = ["user_id", "userId"];

/// What a completed code exchange grants: the user and a token that authenticates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Numeric Qobuz user id, as text.
    pub user_id: String,
    /// The `user_auth_token` to send on every later request.
    pub token: String,
}

/// Builds the URL a browser must open to start the OAuth sign-in.
///
/// # Arguments
///
/// * `app_id` - Qobuz application ID
/// * `redirect_url` - Where Qobuz sends the browser afterwards, with the code in the query
///
/// # Returns
///
/// The fully encoded sign-in URL.
#[must_use]
pub fn login_url(app_id: &str, redirect_url: &str) -> String {
    let params = [
        ("ext_app_id".to_string(), app_id.to_string()),
        ("redirect_url".to_string(), redirect_url.to_string()),
    ];
    build_url_with_params(SIGNIN_ORIGIN, SIGNIN_PATH, &params)
}

/// Reads the authorisation code out of the redirect Qobuz sent the browser to.
///
/// # Arguments
///
/// * `redirect` - The full redirect URL, a request path, or a bare query string
///
/// # Returns
///
/// The decoded code, or `None` if the redirect carries none.
#[must_use]
pub fn code_from_redirect(redirect: &str) -> Option<String> {
    let query = redirect
        .split_once('?')
        .map_or(redirect, |(_, query)| query);
    let query = query.split('#').next().unwrap_or(query);
    CODE_PARAMS.iter().find_map(|wanted| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| percent_decode(value))
            .filter(|value| !value.is_empty())
    })
}

/// Exchanges an authorisation code for a user token via `GET /oauth/callback`.
///
/// # Arguments
///
/// * `client` - HTTP client implementation
/// * `base_url` - API base URL
/// * `app_id` - Qobuz application ID
/// * `private_key` - The OAuth private key extracted from the web player bundle
/// * `code` - The authorisation code from the redirect
///
/// # Returns
///
/// The granted user id and token.
///
/// # Errors
///
/// Returns a `QobuzApiError` if the request fails or the response carries no token or user id.
pub async fn exchange_code(
    client: &dyn HttpClient,
    base_url: &str,
    app_id: &str,
    private_key: &str,
    code: &str,
) -> Result<Grant, QobuzApiError> {
    let url = format!("{base_url}{CALLBACK_ENDPOINT}");
    let params = [
        ("code", code),
        ("private_key", private_key),
        ("app_id", app_id),
    ];
    let response = client.get(&url, &params).await?;
    let value: Value = parse_response(response, CALLBACK_ENDPOINT).await?;

    let token = TOKEN_FIELDS
        .iter()
        .find_map(|field| value.get(field).and_then(Value::as_str))
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthenticationError {
            message: "The OAuth callback returned no token".to_string(),
        })?
        .to_string();
    let user_id = USER_ID_FIELDS
        .iter()
        .find_map(|field| value.get(field))
        .or_else(|| value.get("user")?.get("id"))
        .and_then(id_text)
        .ok_or_else(|| AuthenticationError {
            message: "The OAuth callback returned no user id".to_string(),
        })?;

    info!(user_id, "OAuth code exchanged for a token");
    Ok(Grant { user_id, token })
}

/// Confirms a token with `user/login` the way the web player does after an OAuth exchange.
///
/// # Arguments
///
/// * `client` - HTTP client implementation
/// * `base_url` - API base URL
/// * `token` - The `user_auth_token` to confirm
///
/// # Returns
///
/// The login response, which describes the user and their subscription.
///
/// # Errors
///
/// Returns a `QobuzApiError` if Qobuz rejects the token or the request fails.
pub async fn validate_token(
    client: &dyn HttpClient,
    base_url: &str,
    token: &str,
) -> Result<Value, QobuzApiError> {
    let params = [("extra", "partner")];
    let query = [("extra".to_string(), "partner".to_string())];
    let url = build_url_with_params(base_url, LOGIN_ENDPOINT, &query);
    let response = client.post_form_with_auth(&url, &params, token).await?;
    parse_response(response, LOGIN_ENDPOINT).await
}

/// Renders a JSON id, numeric or textual, as text.
///
/// # Arguments
///
/// * `value` - The JSON value holding the id
///
/// # Returns
///
/// The id as a string, or `None` for any other JSON type.
fn id_text(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

/// Decodes `%XX` escapes and `+` in a query string value.
///
/// # Arguments
///
/// * `text` - The raw query value
///
/// # Returns
///
/// The decoded text, with invalid UTF-8 replaced.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        let escaped = (byte == b'%')
            .then(|| bytes.get(index.saturating_add(1)..index.saturating_add(3)))
            .flatten()
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        if let Some(value) = escaped {
            decoded.push(value);
            index = index.saturating_add(3);
            continue;
        }
        decoded.push(match byte {
            b'+' => b' ',
            other => other,
        });
        index = index.saturating_add(1);
    }
    String::from_utf8_lossy(&decoded).into_owned()
}
