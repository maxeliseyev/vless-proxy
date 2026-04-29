use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub inbound: InboundConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub uuid: Uuid,
    #[serde(default = "default_tls")]
    pub use_tls: bool,
    #[serde(default = "default_security")]
    pub security: String,
}

#[derive(Debug, Deserialize)]
pub struct InboundConfig {
    pub address: String,
    pub port: u16,
    #[serde(default = "socks5")]
    pub protocol: String,
}

fn default_tls() -> bool {
    true
}

fn default_security() -> String {
    "tls".to_string()
}

fn socks5() -> String {
    "socks5".to_string()
}

impl Config {
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server.address, self.server.port)
    }

    pub fn inbound_addr(&self) -> String {
        format!("{}:{}", self.inbound.address, self.inbound.port)
    }
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        if self.server.port == 0 || self.server.port > 65535 {
            anyhow::bail!("Server port must be 1-65535");
        }
        if self.inbound.port == 0 || self.inbound.port > 65535 {
            anyhow::bail!("Inbound port must be 1-65535");
        }
        Ok(())
    }
}