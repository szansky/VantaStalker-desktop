use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use futures_util::{StreamExt, SinkExt};
use url::Url;
use crate::core::models::{WSMessage, WSHistoryItem};
use chrono::Local;

pub async fn connect_and_listen(
    url_str: String,
    tx_ui: UnboundedSender<WSHistoryItem>,
    mut rx_send: UnboundedReceiver<WSMessage>,
) {
    if let Ok(url) = Url::parse(&url_str) {
        match connect_async(url.to_string()).await {
            Ok((ws_stream, _)) => {
                // Log connection success? We can send a special system message or just rely on state.
                let (mut write, mut read) = ws_stream.split();

                // Spawn Reader
                let tx_clone = tx_ui.clone();
                tokio::spawn(async move {
                    while let Some(msg) = read.next().await {
                        if let Ok(msg) = msg {
                            let timestamp = Local::now().format("%H:%M:%S").to_string();
                            let content = match msg {
                                Message::Text(t) => Some(WSMessage::Text(t.to_string())),
                                Message::Binary(b) => Some(WSMessage::Binary(b.to_vec())),
                                Message::Ping(_) => None, // Ignore for history?
                                Message::Pong(_) => None,
                                Message::Close(_) => None,
                                Message::Frame(_) => None,
                            };
                            
                            if let Some(c) = content {
                                let _ = tx_clone.send(WSHistoryItem {
                                    timestamp,
                                    direction: "Received".to_string(),
                                    message: c,
                                });
                            }
                        } else {
                            break; // Connection lost
                        }
                    }
                });

                // Writer Loop
                while let Some(msg) = rx_send.recv().await {
                   let tungsten_msg = match msg.clone() {
                       WSMessage::Text(t) => Message::Text(t.into()),
                       WSMessage::Binary(b) => Message::Binary(b.into()),
                   };
                   
                   if write.send(tungsten_msg).await.is_err() {
                       break;
                   }

                   // Echo back to history as Sent
                   let timestamp = Local::now().format("%H:%M:%S").to_string();
                   let _ = tx_ui.send(WSHistoryItem {
                       timestamp,
                       direction: "Sent".to_string(),
                       message: msg,
                   });
                }
            },
            Err(e) => {
                eprintln!("Failed to connect: {}", e);
            }
        }
    }
}
