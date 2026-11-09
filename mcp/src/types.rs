use thiserror::Error;

// Keep diagnostics independent of HTTP errors, which can contain credentials
// or secret-bearing request/response data.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum McpError {
    #[error("ORBITPORT_URL must be a valid gateway base URL")]
    InvalidGatewayUrl,
    #[error("ORBITPORT_URL requires HTTPS, except for loopback development")]
    InsecureGatewayUrl,
    #[error("ORBITPORT_URL must be a base URL without credentials, path, query or fragment")]
    InvalidGatewayBaseUrl,
    #[error("ORBITPORT_PAT must be set")]
    MissingPat,
    #[error("ORBITPORT_PAT is not a valid bearer credential")]
    InvalidPat,
    #[error("Unknown --allow value; see --help")]
    InvalidToolOptIn,
    #[error("Failed to initialize gateway HTTP client")]
    ClientInitialization,
    #[error("Unable to encode KMS request")]
    RequestEncoding,
    #[error(
        "Gateway request failed or timed out; the operation may have completed. Check its state before retrying."
    )]
    GatewayRequest,
    #[error("Gateway response was interrupted; check operation state before retrying")]
    GatewayResponseInterrupted,
    #[error("Gateway response exceeds the local MCP size limit")]
    ResponseTooLarge,
    #[error("Invalid gateway JSON-RPC response")]
    InvalidRpcResponse,
    #[error("Gateway KMS result must be an object")]
    InvalidRpcResult,
    #[error("Invalid KMS parameters")]
    InvalidParameters,
    #[error("{0}")]
    InvalidParametersDetail(String),
    #[error("The requested KMS resource was not found.")]
    ResourceNotFound,
    #[error("The key or resource does not exist or does not belong to you.")]
    KmsPermissionDenied,
    #[error("The resource is not in a state that allows this KMS operation.")]
    FailedPrecondition,
    #[error("KMS rejected the operation arguments.")]
    InvalidOperationArguments,
    #[error("KMS operation failed; check the resource, permissions and parameters")]
    OperationFailed,
    #[error("Your PAT has expired. Create a new PAT in the Orbitport dashboard.")]
    PatExpired,
    #[error("Your PAT is invalid or revoked. Create a new PAT in the Orbitport dashboard.")]
    InvalidCredential,
    #[error("Insufficient Orbitport credits. Top up your account in the dashboard.")]
    InsufficientCredits,
    #[error("Your Orbitport account is inactive. Contact your account administrator.")]
    AccountInactive,
    #[error("The gateway refused this request.")]
    PermissionDenied,
    #[error("Orbitport rate limit reached. Try again shortly.")]
    RateLimitExceeded,
    #[error("Orbitport is temporarily unavailable. Try again later.")]
    BackendUnavailable,
    #[error("Gateway redirects are not followed. Configure the correct ORBITPORT_URL.")]
    Redirect,
    #[error("The request exceeds the gateway body size limit.")]
    RequestTooLarge,
    #[error("The gateway rejected this request.")]
    GatewayRejected,
    #[error("MCP stdio failed")]
    StdioFailure,
    #[error("Failed to listen for the termination signal")]
    SignalFailure,
}
