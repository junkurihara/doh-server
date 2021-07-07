use crate::odoh::ODoHRotator;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;

use jsonwebtoken::Algorithm;
use std::str::FromStr;

pub enum AlgorithmType {
    HMAC,
    EC,
    RSA,
}

#[cfg(feature = "tls")]
use std::path::PathBuf;

#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    pub listen_address: SocketAddr,
    pub local_bind_address: SocketAddr,
    pub server_address: SocketAddr,
    pub path: String,
    pub max_clients: usize,
    pub timeout: Duration,
    pub clients_count: ClientsCount,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub disable_auth: bool,
    pub validation_key: String,
    pub validation_algorithm: Algorithm,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,

    pub runtime_handle: runtime::Handle,
}

impl Globals {
    pub fn set_validation_algorithm(&mut self, algorithm_str: &str) {
        if let Ok(a) = Algorithm::from_str(algorithm_str) {
            self.validation_algorithm = a;
        } else {
            panic!("Invalid algorithm")
        }
    }
    pub fn get_type(&self) -> AlgorithmType {
        if self.is_hmac() {
            AlgorithmType::HMAC
        } else if self.is_ec() {
            AlgorithmType::EC
        } else {
            AlgorithmType::RSA
        }
    }

    pub fn is_hmac(&self) -> bool {
        self.validation_algorithm == Algorithm::HS512
            || self.validation_algorithm == Algorithm::HS384
            || self.validation_algorithm == Algorithm::HS256
    }

    pub fn is_ec(&self) -> bool {
        self.validation_algorithm == Algorithm::ES256
            || self.validation_algorithm == Algorithm::ES384
    }

    pub fn is_rsa(&self) -> bool {
        self.validation_algorithm == Algorithm::RS256
            || self.validation_algorithm == Algorithm::RS384
            || self.validation_algorithm == Algorithm::RS512
            || self.validation_algorithm == Algorithm::PS256
            || self.validation_algorithm == Algorithm::PS384
            || self.validation_algorithm == Algorithm::PS512
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0
                && self
                    .0
                    .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
                    != Ok(count)
        } {}
        count
    }
}
