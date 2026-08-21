use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use super::limits::{SseGuard, client_ip};
use super::{ApiError, AppState};
use crate::events::MailEvent;

/// `GET /api/addresses/{address}/events` - live stream of new-message events
/// for a single mailbox via Server-Sent Events.
///
/// Subscribes to the shared broadcast channel and forwards only events whose
/// address matches. Lagged/errored broadcast items are dropped; clients recover
/// missed messages through the REST inbox listing.
///
/// Concurrency is capped globally and per client IP (A3); when a cap is hit
/// the request is rejected with `429` before subscribing.
pub async fn events(
    State(state): State<AppState>,
    Path(address): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let ip = client_ip(&headers, peer.ip(), state.config.api_trust_proxy_headers);
    let Some(guard) = state.limits.try_acquire_sse(ip) else {
        return Err(ApiError::TooManyRequests(
            "too many concurrent event streams".to_string(),
        ));
    };

    let address = address.to_ascii_lowercase();
    let rx = state.events.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(move |res| match res {
        Ok(ev) if ev.address == address => Some(to_sse_event(&ev)),
        _ => None,
    });

    Ok(Sse::new(GuardedStream {
        inner: stream,
        _guard: guard,
    })
    .keep_alive(KeepAlive::default()))
}

fn to_sse_event(ev: &MailEvent) -> Result<Event, Infallible> {
    let event = Event::default()
        .event("message")
        .json_data(ev)
        .unwrap_or_else(|_| Event::default().event("message").data("{}"));
    Ok(event)
}

/// Wraps the event stream so the SSE concurrency slot is released exactly when
/// the stream is dropped (client disconnect or server shutdown).
struct GuardedStream<S> {
    inner: S,
    _guard: SseGuard,
}

impl<S: Stream + Unpin> Stream for GuardedStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}
