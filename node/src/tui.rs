use std::io::{self};
use std::time::Duration;
use std::fs;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::message::PeerInfo;
use crate::net::{NetEvent, UiEvent};

pub fn run_tui(mut net_rx: UnboundedReceiver<NetEvent>, ui_tx: UnboundedSender<UiEvent>) {
    // Setup terminal
    let mut stdout = io::stdout();
    enable_raw_mode().unwrap();
    stdout.execute(EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    let mut input = String::new();
    let mut messages: Vec<String> = Vec::new();
    let mut peers: Vec<PeerInfo> = Vec::new();
    let mut should_quit = false;

    while !should_quit {
        // draw
        terminal.draw(|f| ui(f, &messages, &peers, &input)).unwrap();

        // non-blocking poll of events and channel
        if event::poll(Duration::from_millis(50)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            should_quit = true;
                        }
                        KeyCode::Char(ch) => input.push(ch),
                        KeyCode::Backspace => { input.pop(); }
                        KeyCode::Enter => {
                            let text = input.trim().to_string();
                            if !text.is_empty() {
                                if text.starts_with('/') {
                                    handle_command(&text, &ui_tx, &mut should_quit, &peers, &mut messages);
                                } else {
                                    let _ = ui_tx.send(UiEvent::SendText(text));
                                }
                            }
                            input.clear();
                        }
                        _ => {}
                    }
                }
            }
        }

        // drain net events
        while let Ok(ev) = net_rx.try_recv() {
            match ev {
                NetEvent::Chat(msg) => {
                    messages.push(format!("[{}] {}", msg.from, msg.text));
                    if messages.len() > 500 { messages.remove(0); }
                }
                NetEvent::System(s) => {
                    messages.push(format!("[system] {s}"));
                }
                NetEvent::Peers(p) => {
                    peers = p;
                }
            }
        }
    }

    // restore terminal
    disable_raw_mode().ok();
    let mut out = terminal.backend_mut();
    out.execute(LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
}

fn handle_command(
    cmd: &str,
    ui_tx: &UnboundedSender<UiEvent>,
    should_quit: &mut bool,
    peers: &Vec<PeerInfo>,
    messages: &mut Vec<String>,
) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.get(0).copied().unwrap_or("") {
        "/quit" | "/q" => { *should_quit = true; let _ = ui_tx.send(UiEvent::Quit); }
        "/nick" if parts.len() >= 2 => {
            let new = parts[1].to_string();
            let _ = ui_tx.send(UiEvent::ChangeNick(new));
        }
        "/peers" => {
            if peers.is_empty() {
                messages.push("[peers] none".to_string());
            } else {
                for p in peers {
                    messages.push(format!("[peers] {} {}", p.name, p.addr));
                }
            }
        }
        "/connect" if parts.len() >= 2 => {
            let addr = parts[1].to_string();
            messages.push(format!("[connect] trying {}", addr));
            let _ = ui_tx.send(UiEvent::Connect(addr));
        }
        "/me" if parts.len() >= 2 => {
            let action = parts[1..].join(" ");
            let _ = ui_tx.send(UiEvent::Emote(action));
        }
        "/whoami" => {
            let _ = ui_tx.send(UiEvent::QueryName);
        }
        "/clear" => {
            messages.clear();
        }
        "/save" => {
            let path = parts.get(1).cloned().unwrap_or("chatlog.txt");
            let content = messages.join("\n");
            match fs::write(path, content) {
                Ok(_) => messages.push("[save] chat saved".to_string()),
                Err(e) => messages.push(format!("[save] error: {e}")),
            }
        }
        "/help" => {
            messages.push("[help] /nick <name>, /peers, /connect <host:port>, /me <action>, /whoami, /clear, /save [file], /quit".to_string());
        }
        _ => {
            let _ = ui_tx.send(UiEvent::SendText(cmd.to_string()));
        }
    }
}

fn ui(f: &mut ratatui::Frame<'_>, messages: &Vec<String>, peers: &Vec<PeerInfo>, input: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(f.size());

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(75),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    // chat pane
    let items: Vec<ListItem> = messages.iter().map(|m| ListItem::new(m.clone())).collect();
    let chat = List::new(items)
        .block(Block::default().title("Chat").borders(Borders::ALL));
    f.render_widget(chat, mid[0]);

    // peers pane
    let peers_lines: Vec<ListItem> = peers.iter().map(|p| ListItem::new(format!("{}\n{}", p.name, p.addr))).collect();
    let peers_list = List::new(peers_lines).block(Block::default().title("Peers").borders(Borders::ALL));
    f.render_widget(peers_list, mid[1]);

    // input pane
    let input_para = Paragraph::new(input.to_string()).block(Block::default().title("Input (/nick, /peers, /quit)").borders(Borders::ALL));
    f.render_widget(input_para, chunks[1]);
}


