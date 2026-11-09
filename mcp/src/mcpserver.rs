use clap::Parser;
use kms_mcp::{client::GatewayClient, serve, types::McpError};
use kms_mcp_core::ToolPolicy;
use std::process::ExitCode;
use tokio::io::BufReader;

#[derive(Parser)]
#[command(
    version,
    about = "Local stdio MCP server for Orbitport KMS. Credentials are read only from ORBITPORT_PAT."
)]
struct Args {
    #[arg(
        long,
        env = "ORBITPORT_URL",
        default_value = "https://op.spacecomputer.io",
        hide_env_values = true
    )]
    url: String,
    #[arg(
        long,
        default_value = "",
        help = "Comma-separated opt-ins: decrypt,generate-data-key,encapsulate,decapsulate,keystore-get,keystore-delete"
    )]
    allow: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), McpError> {
    let pat = std::env::var("ORBITPORT_PAT").map_err(|_| McpError::MissingPat)?;
    let policy = ToolPolicy::new(&args.allow).map_err(|_| McpError::InvalidToolOptIn)?;
    let client = GatewayClient::new(&args.url, &pat)?;
    tokio::select! {
        result = serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout(), client, policy) =>
            result.map_err(|_| McpError::StdioFailure),
        result = tokio::signal::ctrl_c() => result.map_err(|_| McpError::SignalFailure),
    }
}
