use std::env;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Config {
    pub node_name: String,
    pub room: String,
    pub listen_port: u16,
    pub discovery_url: String,
    pub announce_addr: String,
    pub max_peers: usize,
    // headless test options
    pub headless: bool,
    pub auto_send: Option<String>,
    pub expect_substrings: Vec<String>,
    pub run_duration_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        let node_name = env::var("NODE_NAME").unwrap_or_else(|_| format!("node-{}", Uuid::new_v4().to_string()[..8].to_string()));
        let room = env::var("ROOM").unwrap_or_else(|_| "default".to_string());
        let listen_port = env::var("LISTEN_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(7001);
        let discovery_url = env::var("DISCOVERY_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let announce_addr = env::var("ANNOUNCE_ADDR").unwrap_or_else(|_| format!("127.0.0.1:{}", listen_port));
        let max_peers = env::var("MAX_PEERS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let headless = matches!(env::var("HEADLESS").unwrap_or_else(|_| "0".into()).as_str(), "1" | "true" | "TRUE" | "yes");
        let auto_send = env::var("AUTO_SEND").ok().filter(|s| !s.is_empty());
        let expect_substrings = env::var("EXPECT_SUBSTRINGS").ok()
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_else(|| vec![]);
        let run_duration_secs = env::var("RUN_DURATION_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
        Self { node_name, room, listen_port, discovery_url, announce_addr, max_peers, headless, auto_send, expect_substrings, run_duration_secs }
    }
}


