use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Notify;

use gateway::{logging, plugins, server, service_manager, types::GatewayError};

#[derive(Parser, Debug)]
struct Args {
    #[clap(short = 'p', long, env = "ORBITPORT_HTTP_PORT", default_value = "8080")]
    http_port: u16,
    /// Port for internal-only routes (PAT and agent credential issuance). Must not be published by
    /// any load balancer or Ingress-backed Service.
    #[clap(long, env = "ORBITPORT_INTERNAL_PORT", default_value = "8081")]
    internal_port: u16,
    #[clap(long, env = "ORBITPORT_METRICS_PORT", default_value = "9100")]
    metric_port: u16,
    #[clap(long, env = "ORBITPORT_AUTH_PLUGIN")]
    auth_plugin: String,
    #[clap(long, env = "ORBITPORT_KMS_PLUGIN")]
    kms_plugin: String,
    #[clap(long, env = "ORBITPORT_THRESHOLD_ENABLED", default_value = "false")]
    threshold_enabled: bool,
    #[clap(long, env = "ORBITPORT_THRESHOLD_PLUGIN", default_value = "")]
    threshold_plugin: String,
    #[clap(long, env = "ORBITPORT_THRESHOLD_GROUPS", default_value = "")]
    threshold_groups: String,
    /// Off by default: KMS-only deployments do not run the masterseed plugin
    #[clap(long, env = "ORBITPORT_CTRNG_ENABLED", default_value = "false")]
    ctrng_enabled: bool,
    /// Required when ORBITPORT_CTRNG_ENABLED=true
    #[clap(long, env = "ORBITPORT_MASTERSEED_PLUGIN")]
    masterseed_plugin: Option<String>,
    /// Optional account plugin gRPC URL. When set, JWT-authenticated routes
    /// hold credits via the account plugin before serving the request and
    /// release on downstream failure.
    #[clap(long, env = "ORBITPORT_ACCOUNT_PLUGIN")]
    account_plugin: Option<String>,
    /// Optional patissuer plugin gRPC URL. When set, the gateway serves the
    /// M2M-authorized internal PAT issuance route.
    #[clap(long, env = "ORBITPORT_PATISSUER_PLUGIN")]
    patissuer_plugin: Option<String>,
    /// Rate limit per access token, 4 requests per second
    /// (40 requests per 10 seconds window)
    #[clap(long, env = "ORBITPORT_RATE_LIMIT", default_value = "40")]
    rate_limit: u32,
    #[clap(long, env = "ORBITPORT_RATE_LIMIT_WINDOW", default_value = "10")]
    rate_limit_window: u64,
    #[clap(long, env = "ORBITPORT_BULK_MAX", default_value = "10")]
    bulk_max: usize,
    #[clap(long, env = "ORBITPORT_RPC_BODY_MAX_BYTES", default_value = "65536")]
    rpc_body_max_bytes: u64,
}

impl Args {
    pub fn with_dot_env() -> Self {
        dotenvy::dotenv().ok();
        dotenvy::from_filename(".gateway.env").ok();
        Self::parse()
    }
}

/// PAT revocation is only enforced on the account plugin's Hold path, so an
/// issuer without an account plugin mints tokens that can never be revoked.
fn validate_pat_revocation_gating(
    patissuer_configured: bool,
    account_configured: bool,
) -> Result<(), String> {
    if !patissuer_configured || account_configured {
        return Ok(());
    }
    Err(
        "ORBITPORT_PATISSUER_PLUGIN is set but ORBITPORT_ACCOUNT_PLUGIN is not: PATs would be \
         mintable but never revocable (revocation is enforced on the account plugin's Hold \
         path). Set ORBITPORT_ACCOUNT_PLUGIN."
            .to_string(),
    )
}

/// returns true when `/healthz` on the local HTTP port answers 200
async fn healthz_ok(port: u16) -> bool {
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        stream
            .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut status_line = String::new();
        BufReader::new(stream).read_line(&mut status_line).await?;
        Ok::<_, std::io::Error>(status_line)
    };
    match tokio::time::timeout(Duration::from_secs(3), probe).await {
        Ok(Ok(status_line)) => status_line.split_whitespace().nth(1) == Some("200"),
        _ => false,
    }
}

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    // distroless images have no shell or curl, so container healthchecks run the binary itself
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let port = std::env::var("ORBITPORT_HTTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        std::process::exit(if healthz_ok(port).await { 0 } else { 1 });
    }

    let _log_guard = logging::initialize_logging();

    let start = std::time::Instant::now();

    let args: Args = Args::with_dot_env();
    tracing::info!("Starting orbitport with args: {:?}", args);

    validate_pat_revocation_gating(
        args.patissuer_plugin.is_some(),
        args.account_plugin.is_some(),
    )
    .map_err(|e| {
        tracing::error!("{}", e);
        GatewayError::InternalError(e)
    })?;

    let shutdown = Arc::new(Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => shutdown.notify_waiters(),
                Err(err) => tracing::error!("Failed to listen for shutdown signal: {}", err),
            }
        });
    }

    let masterseed_plugin = match (args.ctrng_enabled, args.masterseed_plugin.as_deref()) {
        (true, Some(url)) if !url.trim().is_empty() => Some(url.trim().to_string()),
        (true, _) => {
            return Err(GatewayError::BadRequest(
                "ORBITPORT_MASTERSEED_PLUGIN is required when ORBITPORT_CTRNG_ENABLED=true"
                    .to_string(),
            ));
        }
        (false, _) => None,
    };

    let mut plugin_urls = vec![args.auth_plugin.to_string(), args.kms_plugin.to_string()];
    if let Some(ref url) = masterseed_plugin {
        plugin_urls.push(url.to_string());
    }
    if let Some(ref url) = args.account_plugin {
        plugin_urls.push(url.to_string());
    }
    if let Some(ref url) = args.patissuer_plugin {
        plugin_urls.push(url.to_string());
    }
    if args.threshold_enabled {
        let threshold_plugin = args.threshold_plugin.trim();
        if threshold_plugin.is_empty() {
            return Err(GatewayError::BadRequest(
                "ORBITPORT_THRESHOLD_PLUGIN is required when ORBITPORT_THRESHOLD_ENABLED=true"
                    .to_string(),
            ));
        }
        plugin_urls.push(threshold_plugin.to_string());
    }

    plugins::wait_for(
        plugin_urls,
        std::time::Duration::from_secs(60),
        shutdown.clone(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed while waiting for plugins to be healthy: {}", e);
        GatewayError::ServiceConnectionError(e.to_string())
    })?;
    let service_manager =
        service_manager::ServiceManager::new(&args.auth_plugin, masterseed_plugin.as_deref())
            .await?;

    let metrics_port = args.metric_port;
    tokio::spawn(async move {
        gateway::metrics::start_server(metrics_port).await;
    });

    let service_manager = Arc::new(service_manager);
    let threshold_groups = if args.threshold_enabled {
        gateway::services::threshold::ThresholdGroupRegistry::from_json(&args.threshold_groups)
            .map_err(|e| GatewayError::BadRequest(e.to_string()))?
    } else {
        gateway::services::threshold::ThresholdGroupRegistry::default()
    };
    let plugin_catalog = Arc::new(gateway::plugins::PluginCatalog::new(
        &args.auth_plugin,
        masterseed_plugin.as_deref(),
        &args.kms_plugin,
        args.account_plugin.as_deref(),
        args.patissuer_plugin.as_deref(),
        args.threshold_enabled,
        args.threshold_plugin.trim(),
        threshold_groups,
    ));

    server::start(
        args.http_port,
        args.internal_port,
        service_manager.clone(),
        plugin_catalog.clone(),
        args.rate_limit,
        args.rate_limit_window,
        args.bulk_max,
        args.rpc_body_max_bytes,
        args.ctrng_enabled,
    )
    .await;

    let time_elapsed = start.elapsed();
    tracing::info!(
        "Orbitport finished after {} seconds",
        time_elapsed.as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{healthz_ok, validate_pat_revocation_gating};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(response).await;
        });
        port
    }

    #[tokio::test]
    async fn healthz_ok_on_200() {
        let port = serve_once(b"HTTP/1.0 200 OK\r\n\r\n").await;
        assert!(healthz_ok(port).await);
    }

    #[tokio::test]
    async fn healthz_fails_on_error_status() {
        let port = serve_once(b"HTTP/1.0 503 Service Unavailable\r\n\r\n").await;
        assert!(!healthz_ok(port).await);
    }

    #[tokio::test]
    async fn healthz_fails_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(!healthz_ok(port).await);
    }

    #[test]
    fn patissuer_without_account_fails_closed() {
        assert!(validate_pat_revocation_gating(true, false).is_err());
    }

    #[test]
    fn other_combinations_pass() {
        assert!(validate_pat_revocation_gating(false, false).is_ok());
        assert!(validate_pat_revocation_gating(false, true).is_ok());
        assert!(validate_pat_revocation_gating(true, true).is_ok());
    }
}
