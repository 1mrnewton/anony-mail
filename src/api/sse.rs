use std::convert::Infallible;

use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use super::AppState;
use crate::events::MailEvent;

/// `GET /api/addresses/{address}/events` - live stream of new-message events
/// for a single mailbox via Server-Sent Events.
///
/// Subscribes to the shared broadcast channel and forwards only events whose
/// address matches. Lagged/errored broadcast items are dropped; clients recover
/// missed messages through the REST inbox listing.
pub async fn events(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let address = address.to_ascii_lowercase();
    let rx = state.events.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(move |res| match res {
        Ok(ev) if ev.address == address => Some(to_sse_event(&ev)),
        _ => None,
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn to_sse_event(ev: &MailEvent) -> Result<Event, Infallible> {
    let event = Event::default()
        .event("message")
        .json_data(ev)
        .unwrap_or_else(|_| Event::default().event("message").data("{}"));
    Ok(event)
}
