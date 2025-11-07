use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::message::{ChatMessage, PeerInfo};
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum UiEvent {
    SendText(String),
    ChangeNick(String),
    Quit,
}

#[derive(Debug, Clone)]
pub enum NetEvent {
    Chat(ChatMessage),
    System(String),
    Peers(Vec<PeerInfo>),
}

pub async fn run_network(
    mut cfg: Config,
    mut ui_rx: mpsc::UnboundedReceiver<UiEvent>,
    ui_tx: mpsc::UnboundedSender<NetEvent>,
    mut connect_rx: mpsc::UnboundedReceiver<String>,
) {
    let listen_addr = SocketAddr::from(([0, 0, 0, 0], cfg.listen_port));
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ui_tx.send(NetEvent::System(format!("Failed to bind: {e}")));
            return;
        }
    };
    info!("listening on {}", listen_addr);

    // broadcast channel for outbound JSON lines to all connections
    let (out_tx, _out_rx) = broadcast::channel::<String>(256);

    // track seen message ids for dedupe (bounded)
    let seen_ids: Arc<Mutex<VecDeque<Uuid>>> = Arc::new(Mutex::new(VecDeque::with_capacity(2048)));
    let seen_set: Arc<Mutex<HashSet<Uuid>>> = Arc::new(Mutex::new(HashSet::with_capacity(4096)));

    // spawn accept loop
    let out_tx_clone = out_tx.clone();
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<(String, String /*src*/)>();

    let accept_task = tokio::spawn(accept_loop(listener, out_tx_clone.clone(), inbound_tx.clone()));

    // currently connected addresses to avoid reconnecting
    let connected_addrs: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // aggregator loop: handle UI events, inbound lines, and connect requests
    loop {
        tokio::select! {
            Some(addr) = connect_rx.recv() => {
                // avoid connecting to self and duplicates
                if addr == cfg.announce_addr { continue; }
                let mut set = connected_addrs.lock();
                if set.contains(&addr) { continue; }
                set.insert(addr.clone());
                let out_tx_c = out_tx.clone();
                let inbound_tx_c = inbound_tx.clone();
                let connected_addrs_c = connected_addrs.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(&addr).await {
                        Ok(stream) => {
                            info!("connected to {addr}");
                            handle_connection(stream, out_tx_c, inbound_tx_c).await;
                        }
                        Err(e) => {
                            warn!("failed to connect to {addr}: {e}");
                        }
                    }
                    // on exit remove from set
                    connected_addrs_c.lock().remove(&addr);
                });
            }
            Some((line, _src)) = inbound_rx.recv() => {
                if let Some(msg) = ChatMessage::try_parse(&line) {
                    let id = msg.id;
                    if !dedupe_check_insert(&seen_ids, &seen_set, id) {
                        continue;
                    }
                    // forward to UI
                    let _ = ui_tx.send(NetEvent::Chat(msg.clone()));
                    // re-broadcast to all peers
                    let _ = out_tx.send(line);
                }
            }
            Some(ev) = ui_rx.recv() => {
                match ev {
                    UiEvent::SendText(text) => {
                        let msg = ChatMessage::new(cfg.node_name.clone(), cfg.room.clone(), text);
                        let line = msg.to_line();
                        // local echo
                        let _ = ui_tx.send(NetEvent::Chat(msg));
                        // broadcast
                        let _ = out_tx.send(line);
                    }
                    UiEvent::ChangeNick(nick) => {
                        cfg.node_name = nick;
                    }
                    UiEvent::Quit => {
                        break;
                    }
                }
            }
        }
    }

    // cleanup
    accept_task.abort();
}

pub(crate) fn dedupe_check_insert(
    ids: &Arc<Mutex<VecDeque<Uuid>>>,
    set: &Arc<Mutex<HashSet<Uuid>>>,
    id: Uuid,
) -> bool {
    let mut s = set.lock();
    if s.contains(&id) { return false; }
    s.insert(id);
    drop(s);
    let mut q = ids.lock();
    q.push_back(id);
    if q.len() > 2000 {
        if let Some(old) = q.pop_front() {
            set.lock().remove(&old);
        }
    }
    true
}

async fn accept_loop(listener: TcpListener, out_tx: broadcast::Sender<String>, inbound_tx: mpsc::UnboundedSender<(String, String)>) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("inbound from {addr}");
                let outbound = out_tx.clone();
                let inbound = inbound_tx.clone();
                tokio::spawn(async move { handle_connection(stream, outbound, inbound).await; });
            }
            Err(e) => {
                error!("accept error: {e}");
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, out_tx: broadcast::Sender<String>, inbound_tx: mpsc::UnboundedSender<(String, String)>) {
    let peer = match stream.peer_addr() { Ok(a) => a.to_string(), Err(_) => "unknown".to_string() };
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    // writer task listens to broadcast channel
    let mut out_rx = out_tx.subscribe();

    let writer_task = tokio::spawn(async move {
        while let Ok(line) = out_rx.recv().await {
            if let Err(_) = writer.write_all(line.as_bytes()).await { break; }
        }
    });

    // read incoming
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let _ = inbound_tx.send((line, peer.clone()));
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    writer_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_works() {
        let ids = Arc::new(Mutex::new(VecDeque::with_capacity(8)));
        let set = Arc::new(Mutex::new(HashSet::with_capacity(8)));
        let id = Uuid::new_v4();
        assert!(dedupe_check_insert(&ids, &set, id));
        assert!(!dedupe_check_insert(&ids, &set, id));
    }
}


