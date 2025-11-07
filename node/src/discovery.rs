use crate::config::Config;
use crate::message::PeerInfo;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{interval, Duration};
use tracing::error;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RegisterBody {
    name: String,
    addr: String,
    room: String,
}

#[derive(Deserialize, Debug, Clone)]
struct GetPeersRespItem {
    name: String,
    addr: String,
}

#[derive(Debug, Clone)]
pub enum DiscToNet {
    ConnectTo(String), // addr
    UpdatePeers(Vec<PeerInfo>),
}

pub async fn run_discovery_task(
    cfg: Config,
    connect_tx: UnboundedSender<String>,
    ui_tx: UnboundedSender<crate::net::NetEvent>,
) {
    let client = reqwest::Client::new();
    let mut tick = interval(Duration::from_secs(15));

    loop {
        // initial tick fires immediately after awaiting once
        tick.tick().await;

        if let Err(e) = register(&client, &cfg).await {
            error!("discovery register error: {e}");
        }

        match get_peers(&client, &cfg).await {
            Ok(peers) => {
                // send to UI
                let _ = ui_tx.send(crate::net::NetEvent::Peers(peers.clone()));
                // request connections
                for p in peers {
                    if p.addr != cfg.announce_addr {
                        let _ = connect_tx.send(p.addr);
                    }
                }
            }
            Err(e) => error!("discovery get_peers error: {e}"),
        }
    }
}

async fn register(client: &reqwest::Client, cfg: &Config) -> anyhow::Result<()> {
    let url = format!("{}/register", cfg.discovery_url);
    let body = RegisterBody { name: cfg.node_name.clone(), addr: cfg.announce_addr.clone(), room: cfg.room.clone() };
    client.post(url).json(&body).send().await?.error_for_status()?;
    Ok(())
}

async fn get_peers(client: &reqwest::Client, cfg: &Config) -> anyhow::Result<Vec<PeerInfo>> {
    let url = format!("{}/peers?room={}", cfg.discovery_url, urlencoding::encode(&cfg.room));
    let resp = client.get(url).send().await?.error_for_status()?;
    let items: Vec<GetPeersRespItem> = resp.json().await?;
    let list = items
        .into_iter()
        .map(|i| PeerInfo { name: i.name, addr: i.addr })
        .collect();
    Ok(list)
}


