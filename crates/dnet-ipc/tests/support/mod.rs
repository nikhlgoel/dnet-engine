//! Test fixtures shared by the IPC test files. Every value is a test value of the right shape; none is, or
//! may become, a real credential.

#![allow(dead_code)]

use dnet_config::amneziawg::{ObfuscationParams, PrivateKey};
use dnet_config::credentials::{
    AmneziaWgCredentials, EndpointCredentials, Hysteria2Bundle, RealityBundle,
};
use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_ipc::protocol::NewEndpoint;

/// Appears in every secret below. If it shows up in an error, a `Debug` string or a log, a secret leaked.
pub const SENTINEL: &str = "SENTINEL-ipc-secret-3f9a";

/// A bundle serving all three profiles.
pub fn credentials() -> EndpointCredentials {
    EndpointCredentials {
        amneziawg: Some(AmneziaWgCredentials {
            client_private_key: PrivateKey::new("1".repeat(64)),
            server_public_key: "2".repeat(64),
            client_address: "10.66.0.2".parse().unwrap(),
            prefix_len: 24,
            obfuscation: ObfuscationParams {
                jc: 4,
                jmin: 40,
                jmax: 70,
                s1: 15,
                s2: 20,
                h1: 1_053_421_987,
                h2: 2_083_245_612,
                h3: 3_175_921_403,
                h4: 4_012_837_465,
            },
            server_port: 51820,
        }),
        hysteria2: Some(Hysteria2Bundle {
            server_port: 44443,
            credentials: Hysteria2Credentials {
                auth_password: Secret::new(format!("{SENTINEL}-auth-0123456789")),
                obfs_password: Secret::new(format!("{SENTINEL}-obfs-0123456789")),
            },
            endpoint: Hysteria2EndpointParams {
                obfs: Hysteria2Obfs::Salamander,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: "edge.example.net".into(),
                    spki_sha256: [7; 32],
                },
            },
        }),
        reality: Some(RealityBundle {
            server_port: 8443,
            credentials: RealityCredentials {
                uuid: Secret::new("bf000d23-0752-40b4-affe-68f7707a9661"),
                short_id: Secret::new("0123456789abcdef"),
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse("www.example.com").unwrap(),
                public_key: RealityPublicKey::parse("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0")
                    .unwrap(),
                flow: VlessFlow::Vision,
            },
        }),
        measure_origin: None,
        session: None,
    }
}

/// A valid new endpoint.
pub fn new_endpoint() -> NewEndpoint {
    NewEndpoint::new("my server", "203.0.113.9", credentials()).unwrap()
}
