use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    #[serde(rename = "type")]
    pub msg_type: String, // "chat"
    pub id: Uuid,
    pub from: String,
    pub room: String,
    pub text: String,
    pub ts: i64, // unix seconds
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub addr: String,
}

impl ChatMessage {
    pub fn new(from: String, room: String, text: String) -> Self {
        let id = Uuid::new_v4();
        let ts = chrono::Utc::now().timestamp();
        Self { msg_type: "chat".to_string(), id, from, room, text, ts }
    }

    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap() + "\n"
    }

    pub fn try_parse(line: &str) -> Option<Self> {
        serde_json::from_str::<ChatMessage>(line).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let msg = ChatMessage::new("alice".into(), "r".into(), "hi".into());
        let line = msg.to_line();
        assert!(line.ends_with('\n'));
        let parsed = ChatMessage::try_parse(line.trim_end()).unwrap();
        assert_eq!(parsed.msg_type, "chat");
        assert_eq!(parsed.from, "alice");
        assert_eq!(parsed.room, "r");
        assert_eq!(parsed.text, "hi");
        assert_eq!(parsed.id, msg.id);
    }
}


