use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arcmint_core::tls::load_tls_client_config;
use reqwest::Client;
use tokio_rustls::rustls::ClientConfig;
use tracing::warn;

use crate::CliConfig;

#[derive(Clone)]
pub struct AdversaryClient {
    pub client: Client,
}

impl AdversaryClient {
    pub fn new(config: &CliConfig) -> Result<Self> {
        let mut builder = Client::builder().timeout(Duration::from_secs(config.timeout_secs));

        if let Some(ca_cert) = &config.ca_cert {
            let tls_config: ClientConfig = load_tls_client_config(ca_cert.as_path(), None, None)?;
            builder = builder.use_preconfigured_tls(Arc::new(tls_config));
        } else {
            warn!("AdversaryClient starting without CA cert, accepting invalid TLS certs (development only)");
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build()?;

        Ok(AdversaryClient { client })
    }
}
