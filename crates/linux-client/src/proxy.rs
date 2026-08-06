use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use tokio::{net::TcpListener as TokioTcpListener, runtime::Builder, time::timeout};

use crate::socks;

const ACCEPT_POLL: Duration = Duration::from_millis(500);

pub(crate) struct ProxyServerGuard {
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProxyServerGuard {
    pub(crate) fn start(
        listen: SocketAddrV4,
        dns_server: Ipv4Addr,
        mark: u32,
        stopping: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        if !listen.ip().is_loopback() || listen.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy listener must use 127.0.0.0/8 and a nonzero port",
            ));
        }
        let listener = TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let worker_stopping = Arc::clone(&stopping);
        let worker = thread::Builder::new()
            .name("mousevpn-socks5".to_owned())
            .spawn(move || {
                let runtime = match Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        eprintln!("MouseVPN proxy runtime failed: {error}");
                        worker_stopping.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                runtime.block_on(run(listener, dns_server, mark, worker_stopping));
            })?;
        Ok(Self {
            stopping,
            worker: Some(worker),
        })
    }
}

impl Drop for ProxyServerGuard {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

async fn run(listener: TcpListener, dns_server: Ipv4Addr, mark: u32, stopping: Arc<AtomicBool>) {
    let listener = match TokioTcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("MouseVPN proxy listener failed: {error}");
            stopping.store(true, Ordering::Relaxed);
            return;
        }
    };
    while !stopping.load(Ordering::Relaxed) {
        match timeout(ACCEPT_POLL, listener.accept()).await {
            Ok(Ok((client, _))) => {
                tokio::spawn(async move {
                    if let Err(error) = socks::serve_client(client, dns_server, mark).await {
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                        ) {
                            eprintln!("SOCKS5 connection failed: {error}");
                        }
                    }
                });
            }
            Ok(Err(error)) => {
                eprintln!("MouseVPN proxy accept failed: {error}");
                stopping.store(true, Ordering::Relaxed);
                return;
            }
            Err(_) => {}
        }
    }
}
