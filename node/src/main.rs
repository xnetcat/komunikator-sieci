mod config;
mod discovery;
mod message;
mod net;
mod tui;

use std::thread;

use config::Config;
use tokio::sync::mpsc;
use tracing::info;

#[tokio::main]
async fn main() {
    init_tracing();
    let mut cfg = Config::from_env();

    info!("node name={} room={} listen={} announce={}", cfg.node_name, cfg.room, cfg.listen_port, cfg.announce_addr);
    if cfg.headless {
        run_headless(cfg).await;
        return;
    }

    // Channels: UI <-> Net
    let (ui_to_net_tx, ui_to_net_rx) = mpsc::unbounded_channel();
    let (net_to_ui_tx, net_to_ui_rx) = mpsc::unbounded_channel();
    // discovery -> net connect requests
    let (connect_tx, connect_rx) = mpsc::unbounded_channel();

    // Run network core
    let net_cfg = cfg.clone();
    let net_handle = tokio::spawn(net::run_network(net_cfg, ui_to_net_rx, net_to_ui_tx.clone(), connect_rx));

    // Run discovery integration
    let disc_cfg = cfg.clone();
    let disc_handle = tokio::spawn(discovery::run_discovery_task(disc_cfg, connect_tx.clone(), net_to_ui_tx.clone()));

    // Run TUI on a blocking thread
    let ui_handle = thread::spawn(move || {
        tui::run_tui(net_to_ui_rx, ui_to_net_tx);
    });

    // Wait for UI to exit (e.g., /quit), then abort background tasks cleanly
    let _ = ui_handle.join();
    net_handle.abort();
    disc_handle.abort();
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

async fn run_headless(cfg: Config) {
    use tokio::time::{sleep, Duration, Instant};
    use net::{NetEvent, UiEvent};

    let (ui_to_net_tx, ui_to_net_rx) = mpsc::unbounded_channel();
    let (net_to_ui_tx, mut net_to_ui_rx) = mpsc::unbounded_channel();
    let (connect_tx, connect_rx) = mpsc::unbounded_channel();

    let net_handle = tokio::spawn(net::run_network(cfg.clone(), ui_to_net_rx, net_to_ui_tx.clone(), connect_rx));
    let disc_handle = tokio::spawn(discovery::run_discovery_task(cfg.clone(), connect_tx.clone(), net_to_ui_tx.clone()));

    // auto-send if configured (after delay for peers to connect)
    if let Some(text) = cfg.auto_send.clone() {
        let tx = ui_to_net_tx.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(3)).await;
            let _ = tx.send(UiEvent::SendText(text));
        });
    }

    let deadline = Instant::now() + Duration::from_secs(cfg.run_duration_secs);
    let mut received: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            _ = sleep(Duration::from_millis(50)) => {},
            Some(ev) = net_to_ui_rx.recv() => {
                if let NetEvent::Chat(msg) = ev {
                    let line = format!("[{}] {}", msg.from, msg.text);
                    println!("RECV {line}");
                    received.push(line);
                }
            }
        }
        if Instant::now() >= deadline { break; }
    }

    // Evaluate expectations
    let mut missing: Vec<String> = vec![];
    for exp in &cfg.expect_substrings {
        if !received.iter().any(|l| l.contains(exp)) {
            missing.push(exp.clone());
        }
    }

    if missing.is_empty() {
        println!("TEST_PASS");
        std::process::exit(0);
    } else {
        eprintln!("TEST_FAIL missing: {}", missing.join(", "));
        std::process::exit(1);
    }
}


