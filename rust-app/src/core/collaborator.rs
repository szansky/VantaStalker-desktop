use axum::{
    routing::any,
    Router,
    extract::{Request, ConnectInfo},
    body::Body,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;
use crate::core::models::OASTInteraction;
use chrono::Local;

// We need a way to send interactions back to UI.
// Since Axum handlers are async and stateless, we usually pass state via Extension or State.

#[derive(Clone)]
struct AppState {
    tx: UnboundedSender<OASTInteraction>,
}

pub async fn start_collaborator_server(port: u16, tx: UnboundedSender<OASTInteraction>) {
    let state = AppState { tx };

    let app = Router::new()
        .route("/{*path}", any(handler))
        .route("/", any(handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    // Log start (we can't easily log to UI from here without channel, but we have tx)
    // We assume the successful spawn is enough.
    
    if let Ok(listener) = TcpListener::bind(addr).await {
         axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap_or(());
    } else {
        eprintln!("Failed to bind to port {}", port);
    }
}

async fn handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> String {
    let timestamp = Local::now().format("%H:%M:%S").to_string();
    let src_ip = addr.ip().to_string();
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    
    // To read body we need to consume it.
    let (_parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap_or_default(); // Limit 1MB
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    
    // headers could be interesting too but let's stick to basic OAST fields for MVP
    
    let interaction = OASTInteraction {
        id: uuid::Uuid::new_v4().to_string(), // Or extract from path if present? For now just random ID locally
        timestamp,
        src_ip,
        method,
        path,
        query,
        body: body_str,
    };
    
    let _ = state.tx.send(interaction);
    
    // Return empty 200 OK to be stealthy
    "".to_string()
}
