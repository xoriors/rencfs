use anyhow::{Context, Result};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
// UPDATED IMPORT: Added OAuth2TokenResponse based on compiler hint
use openidconnect::{
    AuthenticationFlow, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    RedirectUrl, Scope, RefreshToken, OAuth2TokenResponse,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;
use webbrowser;

/// Authenticates with Google.
/// 
/// If `stored_refresh_token` is provided, it tries to use it to silently refresh the session.
/// If that fails or no token is provided, it triggers the full browser flow.
/// 
/// Returns the valid Refresh Token string to be saved.
pub async fn authenticate_google(
    client_id: String, 
    client_secret: String,
    stored_refresh_token: Option<String>
) -> Result<String> {
    
    // 1. Setup Client
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

    // 2. Try Silent Auth (Refresh Token) if available
    if let Some(token_str) = stored_refresh_token {
        println!("Validating cached Google session...");
        let refresh_token = RefreshToken::new(token_str.clone());
        
        let response = client
            .exchange_refresh_token(&refresh_token)
            .request_async(async_http_client)
            .await;

        match response {
            Ok(_) => {
                println!("Google session is valid. Skipping browser.");
                return Ok(token_str); // Return the existing token as it is still valid
            },
            Err(_) => {
                println!("Cached session expired or invalid. Re-authenticating...");
                // Fall through to browser login
            }
        }
    }

    // 3. Browser Login Flow
    println!("Initiating Google 2FA...");

    let (authorize_url, csrf_state, _nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        // CRITICAL: Request offline access to get a Refresh Token
        .add_extra_param("access_type", "offline") 
        // Force consent to ensure we get a refresh token every time we do the full flow
        .add_extra_param("prompt", "consent") 
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

        println!("Google Authentication successful.");

        // Extract the Refresh Token to save it
        let refresh_token = token_response.refresh_token()
            .ok_or_else(|| anyhow::anyhow!("Google did not return a refresh token (check access_type=offline)"))?;

        Ok(refresh_token.secret().clone())
    } else {
        Err(anyhow::anyhow!("Failed to receive connection from browser"))
    }
}