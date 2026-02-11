// src/auth.rs
use anyhow::{Context, Result};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
// UPDATED IMPORT: Added TokenResponse (for id_token() method)
use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    RedirectUrl, Scope, RefreshToken, OAuth2TokenResponse, TokenResponse,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;
use webbrowser;

/// Authenticates with Google.
/// 
/// Triggers a browser flow to authenticate the user.
/// 
/// If `expected_sub` is provided, it verifies that the authenticated user's
/// subject ID matches the expected one.
/// 
/// Returns a tuple: (Refresh Token, Subject ID)
pub async fn authenticate_google(
    client_id: String, 
    client_secret: String,
    expected_sub: Option<String>
) -> Result<(String, String)> {
    
    let google_issuer = IssuerUrl::new("https://accounts.google.com".to_string())?;

    let provider_metadata = CoreProviderMetadata::discover_async(google_issuer, async_http_client)
        .await
        .context("Failed to discover Google OIDC configuration")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080".to_string())?);

    println!("Initiating Google 2FA (Passkey Check)...");

    // keep the `nonce` to verify the ID token later
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_extra_param("access_type", "offline") 
        .add_extra_param("prompt", "login") // Force login UI
        .add_extra_param("max_age", "0")    // Force fresh authentication (Passkey)
        .url();

    println!("Opening browser for authentication...");
    if webbrowser::open(authorize_url.as_str()).is_err() {
        println!("Please open this URL in your browser:\n{}", authorize_url);
    }

    let listener = TcpListener::bind("127.0.0.1:8080")?;
    
    if let Some(stream) = listener.incoming().next() {
        let mut stream = stream?;
        let code;
        let state;
        
        {
            let mut reader = BufReader::new(&stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line)?;

            let redirect_url = request_line.split_whitespace().nth(1).unwrap_or("/");
            let url = Url::parse(&("http://localhost".to_string() + redirect_url))?;

            let code_pair = url.query_pairs().find(|(key, _)| key == "code");
            let state_pair = url.query_pairs().find(|(key, _)| key == "state");

            if let (Some((_, c)), Some((_, s))) = (code_pair, state_pair) {
                code = c.into_owned();
                state = s.into_owned();
            } else {
                return Err(anyhow::anyhow!("Failed to retrieve auth code"));
            }
        }

        let response = "HTTP/1.1 200 OK\r\n\r\nGoogle Auth Successful! You can close this window.";
        stream.write_all(response.as_bytes())?;

        if state != *csrf_state.secret() {
            return Err(anyhow::anyhow!("CSRF state mismatch"));
        }

        let token_response = client
            .exchange_code(openidconnect::AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .context("Failed to exchange auth code for token")?;

        // verify ID token and check subject
        let id_token = token_response.id_token()
            .ok_or_else(|| anyhow::anyhow!("Google did not return an ID token"))?;
        
        let claims = id_token.claims(&client.id_token_verifier(), &nonce)
            .context("Failed to verify ID token claims")?;
        
        let subject = claims.subject().to_string();

        if let Some(expected) = &expected_sub {
            if *expected != subject {
                return Err(anyhow::anyhow!(
                    "Security Alert: Authenticated user ({}) does not match the owner ({})!", 
                    subject, expected
                ));
            }
        } else {
            println!("Authenticated as user ID: {}", subject);
        }

        println!("Google Authentication and Identity Verification successful.");

       let refresh_token = token_response.refresh_token()
            .map(|t| t.secret().clone())
            .unwrap_or_else(String::new);

        Ok((refresh_token, subject))
    } else {
        Err(anyhow::anyhow!("Failed to receive connection from browser"))
    }
}