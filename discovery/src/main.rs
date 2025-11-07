use std::{collections::HashMap, net::SocketAddr, time::Duration};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tracing::info;

const PRUNE_INTERVAL_SECS: u64 = 15;
const ENTRY_TTL_SECS: i64 = 60; // TTL for registrations

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegisterBody {
    name: String,
    addr: String,
    room: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerInfo {
    name: String,
    addr: String,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    name: String,
    addr: String,
    last_seen: DateTime<Utc>,
}

#[derive(Clone, Default)]
struct AppState {
    // room -> Vec<PeerEntry>
    rooms: std::sync::Arc<Mutex<HashMap<String, Vec<PeerEntry>>>>,
}

#[derive(Debug, Deserialize)]
struct PeersQuery {
    room: String,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let state = AppState::default();

    // background pruning
    tokio::spawn(prune_task(state.clone()));

    let app = build_app(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!(%addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn prune_task(state: AppState) {
    let mut tick = interval(Duration::from_secs(PRUNE_INTERVAL_SECS));
    loop {
        tick.tick().await;
        let now = Utc::now();
        let mut rooms = state.rooms.lock();
        for (_room, peers) in rooms.iter_mut() {
            peers.retain(|p| (now - p.last_seen).num_seconds() < ENTRY_TTL_SECS);
        }
    }
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/peers", get(peers))
        .with_state(state)
}

async fn register(State(state): State<AppState>, Json(body): Json<RegisterBody>) -> impl IntoResponse {
    let now = Utc::now();
    let mut rooms = state.rooms.lock();
    let peers = rooms.entry(body.room.clone()).or_default();

    // upsert by name or address
    if let Some(existing) = peers.iter_mut().find(|p| p.name == body.name || p.addr == body.addr) {
        existing.addr = body.addr.clone();
        existing.name = body.name.clone();
        existing.last_seen = now;
    } else {
        peers.push(PeerEntry {
            name: body.name.clone(),
            addr: body.addr.clone(),
            last_seen: now,
        });
    }

    (StatusCode::OK, "ok")
}

async fn peers(State(state): State<AppState>, Query(q): Query<PeersQuery>) -> impl IntoResponse {
    let now = Utc::now();
    let rooms = state.rooms.lock();
    let mut res: Vec<PeerInfo> = vec![];
    if let Some(list) = rooms.get(&q.room) {
        for p in list {
            if (now - p.last_seen).num_seconds() < ENTRY_TTL_SECS {
                res.push(PeerInfo {
                    name: p.name.clone(),
                    addr: p.addr.clone(),
                });
            }
        }
    }
    Json(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::body::{to_bytes, Body}; // to aggregate response body
    use tower::util::ServiceExt; // for `oneshot`
    const BODY_LIMIT: usize = 64 * 1024;

    #[tokio::test]
    async fn register_and_list_peers() {
        let state = AppState::default();
        let app = build_app(state.clone());

        // register alice
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&RegisterBody { name: "alice".into(), addr: "127.0.0.1:7001".into(), room: "r".into() }).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // register bob
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&RegisterBody { name: "bob".into(), addr: "127.0.0.1:7002".into(), room: "r".into() }).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // list peers
        let req = Request::builder()
            .method("GET")
            .uri("/peers?room=r")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), BODY_LIMIT).await.unwrap();
        let peers: Vec<PeerInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[tokio::test]
    async fn peers_filter_expired() {
        let state = AppState::default();
        {
            let mut rooms = state.rooms.lock();
            rooms.insert("x".into(), vec![
                PeerEntry { name: "old".into(), addr: "1.2.3.4:1".into(), last_seen: Utc::now() - chrono::Duration::seconds(ENTRY_TTL_SECS + 1) },
                PeerEntry { name: "new".into(), addr: "1.2.3.4:2".into(), last_seen: Utc::now() },
            ]);
        }
        let app = build_app(state);
        let req = Request::builder().method("GET").uri("/peers?room=x").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), BODY_LIMIT).await.unwrap();
        let peers: Vec<PeerInfo> = serde_json::from_slice(&body).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "new");
    }
}


