use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arcmint_core::tls::load_tls_client_config;
use reqwest::Client;
use tokio_rustls::rustls::ClientConfig;

use crate::CliConfig;

#[derive(Clone)]
pub struct AdversaryClient {
    pub client: Client,
}

impl AdversaryClient {
    pub fn new(config: &CliConfig) -> Result<Self> {
        let mut builder = Client::builder().timeout(Duration::from_secs(config.timeout_secs));

        let ca_cert = config
            .ca_cert
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--ca-cert is required; TLS certificate validation cannot be disabled"))?;
        let tls_config: ClientConfig = load_tls_client_config(ca_cert.as_path(), None, None)?;
        builder = builder.use_preconfigured_tls(Arc::new(tls_config));

        let client = builder.build()?;

        Ok(AdversaryClient { client })
    }
}
