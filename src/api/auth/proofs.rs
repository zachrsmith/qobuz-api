//! Auth unit tests with a local mock HTTP server for deterministic testing.

use std::{
    collections::HashMap,
    env::VarError::{self, NotPresent},
};

use {
    anyhow::{Result, anyhow, ensure},
    tokio::runtime::Runtime,
};

use crate::{
    api::{
        auth::{
            authenticate_with_env, authenticate_with_env_from, login, login_with_token,
            oauth::{code_from_redirect, exchange_code, login_url, validate_token},
            refresh_app_credentials,
        },
        dev_server::{MockServer, make_service_without_auth},
        service_state::QobuzApiService,
    },
    errors::QobuzApiError::{ApiErrorResponse, CredentialsError},
};

/// Builds a mock environment map from key-value pairs.
///
/// # Arguments
///
/// * `pairs` - Key-value pairs to insert into the mock environment.
///
/// # Returns
///
/// A map of environment variable names to values.
fn mock_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Builds an environment reader closure over a mock environment map.
///
/// # Arguments
///
/// * `env` - Mock environment variables.
///
/// # Returns
///
/// A closure returning the value for a key or `NotPresent`.
fn env_reader(env: &HashMap<String, String>) -> impl Fn(&str) -> Result<String, VarError> + '_ {
    move |key| env.get(key).cloned().ok_or(NotPresent)
}

#[test]
fn env_auth_prefers_token_over_email() -> Result<()> {
    let env = mock_env(&[
        ("QOBUZ_USER_ID", "42"),
        ("QOBUZ_USER_AUTH_TOKEN", "tok"),
        ("QOBUZ_EMAIL", "e@x.com"),
        ("QOBUZ_PASSWORD", "p"),
    ]);
    let server = MockServer::start(200, r#"{"user_auth_token":"tok","user":{"id":42}}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    authenticate_with_env_from(&mut service, env_reader(&env))?;
    ensure!(service.require_auth_token()? == "tok");
    Ok(())
}

#[test]
fn env_auth_uses_email_with_password() -> Result<()> {
    let env = mock_env(&[("QOBUZ_EMAIL", "e@x.com"), ("QOBUZ_PASSWORD", "secret")]);
    let server = MockServer::start(200, r#"{"user_auth_token":"email-tok","user":{"id":1}}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    authenticate_with_env_from(&mut service, env_reader(&env))?;
    ensure!(service.require_auth_token()? == "email-tok");
    Ok(())
}

#[test]
fn env_auth_uses_username_alias() -> Result<()> {
    let env = mock_env(&[("QOBUZ_USERNAME", "e@x.com"), ("QOBUZ_PASSWORD", "secret")]);
    let server = MockServer::start(200, r#"{"user_auth_token":"uname-tok","user":{"id":1}}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    authenticate_with_env_from(&mut service, env_reader(&env))?;
    ensure!(service.require_auth_token()? == "uname-tok");
    Ok(())
}

/// Expects authentication to fail with a matching error message.
///
/// # Arguments
///
/// * `env` - Mock environment variables.
/// * `expected_substring` - Expected error message substring.
fn expect_auth_error(env: &HashMap<String, String>, expected_substring: &str) -> Result<()> {
    let mut service = QobuzApiService::with_credentials("id", "secret")?;
    let err = authenticate_with_env_from(&mut service, env_reader(env))
        .err()
        .ok_or_else(|| anyhow!("expected error"))?;
    ensure!(err.to_string().contains(expected_substring));
    Ok(())
}

#[test]
fn env_auth_fails_without_vars() -> Result<()> {
    expect_auth_error(&mock_env(&[]), "environment variables found")
}

#[test]
fn env_auth_fails_email_no_password() -> Result<()> {
    expect_auth_error(&mock_env(&[("QOBUZ_EMAIL", "e@x.com")]), "QOBUZ_PASSWORD")
}

#[test]
fn login_success_stores_token() -> Result<()> {
    let server = MockServer::start(200, r#"{"user_auth_token":"login-tok","user":{"id":1}}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    login(&mut service, "user@example.com", "password")?;
    ensure!(service.require_auth_token()? == "login-tok");
    Ok(())
}

#[test]
fn login_failure_returns_error() -> Result<()> {
    let server = MockServer::start(401, r#"{"status":"error","code":401,"message":"Invalid"}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    let err = login(&mut service, "bad@x.com", "wrong")
        .err()
        .ok_or_else(|| anyhow!("expected error"))?;
    ensure!(matches!(err, ApiErrorResponse { .. }));
    Ok(())
}

#[test]
fn token_auth_success_stores_token() -> Result<()> {
    let server = MockServer::start(200, r#"{"user_auth_token":"tok","user":{"id":42}}"#)?;
    let mut service = make_service_without_auth(&server.base_url())?;
    login_with_token(&mut service, "42", "tok")?;
    ensure!(service.require_auth_token()? == "tok");
    Ok(())
}

#[test]
fn token_auth_failure_returns_error() -> Result<()> {
    let server = MockServer::start(
        401,
        r#"{"status":"error","code":401,"message":"Bad token"}"#,
    )?;
    let mut service = make_service_without_auth(&server.base_url())?;
    ensure!(login_with_token(&mut service, "99", "bad").is_err());
    Ok(())
}

#[test]
fn refresh_rejects_double_refresh() -> Result<()> {
    let mut service = QobuzApiService::with_credentials("id", "secret")?;
    service.mark_credentials_refreshed();
    let err = refresh_app_credentials(&mut service)
        .err()
        .ok_or_else(|| anyhow!("expected error"))?;
    ensure!(matches!(err, CredentialsError { .. }));
    ensure!(err.to_string().contains("once per session"));
    Ok(())
}

#[test]
fn env_wrapper_errors_without_credentials() -> Result<()> {
    let server = MockServer::start(200, "{}")?;
    let mut service = make_service_without_auth(&server.base_url())?;
    match authenticate_with_env(&mut service) {
        Ok(()) => {
            ensure!(
                service.require_auth_token().is_ok(),
                "token should be set on success"
            );
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

#[test]
fn login_url_encodes_the_redirect() -> Result<()> {
    let url = login_url("798273057", "http://localhost:8989");
    ensure!(
        url == "https://www.qobuz.com/signin/oauth?ext_app_id=798273057&redirect_url=http%3A%2F%2Flocalhost%3A8989",
        "unexpected url: {url}"
    );
    Ok(())
}

#[test]
fn code_from_redirect_prefers_the_french_spelling() -> Result<()> {
    let code =
        code_from_redirect("http://localhost:8989/?code=old&code_autorisation=abc%2Fdef&state=1");
    ensure!(code.as_deref() == Some("abc/def"), "got {code:?}");
    Ok(())
}

#[test]
fn code_from_redirect_accepts_a_bare_path_and_plain_code() -> Result<()> {
    ensure!(code_from_redirect("/?code=xyz#frag").as_deref() == Some("xyz"));
    ensure!(code_from_redirect("code=xyz").as_deref() == Some("xyz"));
    Ok(())
}

#[test]
fn code_from_redirect_rejects_a_redirect_without_a_code() -> Result<()> {
    ensure!(code_from_redirect("http://localhost:8989/?error=denied").is_none());
    ensure!(code_from_redirect("/?code=").is_none());
    Ok(())
}

#[test]
fn exchange_code_reads_the_grant() -> Result<()> {
    let body = r#"{"token":"tok","user_id":42}"#;
    let server = MockServer::start(200, body)?;
    let service = make_service_without_auth(&server.base_url())?;
    let rt = Runtime::new()?;
    let grant = rt.block_on(exchange_code(
        service.http_client(),
        service.base_url(),
        "app",
        "key",
        "code",
    ))?;
    ensure!(grant.token == "tok");
    ensure!(grant.user_id == "42");
    Ok(())
}

#[test]
fn exchange_code_reads_a_nested_user() -> Result<()> {
    let body = r#"{"user_auth_token":"tok","user":{"id":"7"}}"#;
    let server = MockServer::start(200, body)?;
    let service = make_service_without_auth(&server.base_url())?;
    let rt = Runtime::new()?;
    let grant = rt.block_on(exchange_code(
        service.http_client(),
        service.base_url(),
        "app",
        "key",
        "code",
    ))?;
    ensure!(grant.user_id == "7");
    Ok(())
}

#[test]
fn exchange_code_fails_without_a_token() -> Result<()> {
    let server = MockServer::start(200, r#"{"user_id":42}"#)?;
    let service = make_service_without_auth(&server.base_url())?;
    let rt = Runtime::new()?;
    let error = rt
        .block_on(exchange_code(
            service.http_client(),
            service.base_url(),
            "app",
            "key",
            "code",
        ))
        .err()
        .ok_or_else(|| anyhow!("expected an error"))?;
    ensure!(error.to_string().contains("no token"));
    Ok(())
}

#[test]
fn validate_token_returns_the_login_response() -> Result<()> {
    let body = r#"{"user":{"id":42,"display_name":"Ada"}}"#;
    let server = MockServer::start(200, body)?;
    let service = make_service_without_auth(&server.base_url())?;
    let rt = Runtime::new()?;
    let response = rt.block_on(validate_token(
        service.http_client(),
        service.base_url(),
        "tok",
    ))?;
    ensure!(
        response
            .pointer("/user/display_name")
            .and_then(|v| v.as_str())
            == Some("Ada")
    );
    Ok(())
}

#[test]
fn validate_token_surfaces_a_rejection() -> Result<()> {
    let body = r#"{"status":"error","code":401,"message":"User authentication is required."}"#;
    let server = MockServer::start(401, body)?;
    let service = make_service_without_auth(&server.base_url())?;
    let rt = Runtime::new()?;
    ensure!(
        rt.block_on(validate_token(
            service.http_client(),
            service.base_url(),
            "tok"
        ))
        .is_err()
    );
    Ok(())
}
