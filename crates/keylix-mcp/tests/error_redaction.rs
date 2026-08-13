//! Diagnostic redaction coverage for the MCP HTTP adapter.

use core::fmt;

use keylix_mcp::DpopStreamableHttpClientError;
use rmcp::transport::streamable_http_client::StreamableHttpError;

const SEEDED_SECRET: &str = "secret-access-token-keylix-mcp-redaction";

#[derive(Debug)]
struct SensitiveBackendError;

impl fmt::Display for SensitiveBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SEEDED_SECRET)
    }
}

impl std::error::Error for SensitiveBackendError {}

#[test]
fn backend_error_debug_and_display_do_not_expose_sensitive_detail() {
    let error = DpopStreamableHttpClientError::Inner(Box::new(StreamableHttpError::Client(
        SensitiveBackendError,
    )));

    let debug = format!("{error:?}");
    let display = error.to_string();

    assert!(!debug.contains(SEEDED_SECRET));
    assert!(!display.contains(SEEDED_SECRET));
    assert_eq!(display, "wrapped MCP HTTP client failed");
}
