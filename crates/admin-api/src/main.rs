use std::{
    env,
    error::Error,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use mousevpn_admin_api::{router, AdminToken};
use mousevpn_server::ServerState;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let raw_token = env::var("MOUSEVPN_ADMIN_TOKEN").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "MOUSEVPN_ADMIN_TOKEN must contain at least 32 bytes",
        )
    })?;
    let token = AdminToken::new(raw_token)?;
    let address = SocketAddr::from(([127, 0, 0, 1], 9797));
    let listener = TcpListener::bind(address).await?;
    let state = Arc::new(Mutex::new(ServerState::new(64)));

    println!("MouseVPN admin API listening on http://{address}");
    axum::serve(listener, router(state, token)).await?;
    Ok(())
}
