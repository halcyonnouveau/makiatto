// Copied from axum-extra extract::Host
// Source: https://github.com/tokio-rs/axum/blob/b1cd1c17cb82fa26b526e0b9d99a0ac4794e139e/axum-extra/src/extract/host.rs
// See: https://github.com/tokio-rs/axum/issues/3442

use std::convert::Infallible;

use axum::RequestPartsExt;
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::{
    header::{FORWARDED, HeaderMap},
    request::Parts,
    uri::Authority,
};

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

#[derive(Debug, Clone)]
pub struct Host(pub String);

#[derive(Debug, Copy, Clone)]
pub enum HostRejection {
    FailedToResolveHost,
}

impl axum::response::IntoResponse for HostRejection {
    fn into_response(self) -> axum::response::Response {
        axum::http::StatusCode::BAD_REQUEST.into_response()
    }
}

impl<S> FromRequestParts<S> for Host
where
    S: Send + Sync,
{
    type Rejection = HostRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Option<Self>>()
            .await
            .ok()
            .flatten()
            .ok_or(HostRejection::FailedToResolveHost)
    }
}

impl<S> OptionalFromRequestParts<S> for Host
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        if let Some(host) = parse_forwarded(&parts.headers) {
            return Ok(Some(Self(host.to_owned())));
        }

        if let Some(host) = parts
            .headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(Self(host.to_owned())));
        }

        if let Some(host) = parts
            .headers
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(Self(host.to_owned())));
        }

        if let Some(authority) = parts.uri.authority() {
            return Ok(Some(Self(parse_authority(authority).to_owned())));
        }

        Ok(None)
    }
}

fn parse_forwarded(headers: &HeaderMap) -> Option<&str> {
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;
    let first_value = forwarded_values.split(',').next()?;

    first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    })
}

fn parse_authority(auth: &Authority) -> &str {
    auth.as_str()
        .rsplit('@')
        .next()
        .expect("split always has at least 1 item")
}
