//! Race the real profiles against the running Docker harness (T059, T068 groundwork).
//!
//! Needs `docker compose up` in `testing/harness` (the endpoint then writes
//! `.state/hy2-client.json` and `.state/reality-client.json`) and the vendored core
//! (`cargo xtask fetch-vendor`). Needs no elevation: every probe is a SOCKS-only core on
//! loopback, so nothing here touches the routing table.
//!
//! Run it with no condition applied for a baseline, then apply a hostile condition with
//! `testing/harness/harness.ps1 apply <ID>` and run it again:
//!
//! - `H2`  total UDP block: Hysteria 2 must fail and VLESS+REALITY (TCP) must win (HV-02);
//! - `H9`  bandwidth ceiling: a profile that connects but crawls must not win (HV-12).
//!
//! ```text
//! cargo run -p dnet-probe --example race -- [--endpoint 127.0.0.1] [--bytes 2000000]
//! ```
//!
//! Prints each profile's probe and verdict, then the race's decision.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use dnet_config::hysteria2::{
    Hysteria2ClientParams, Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs,
    Hysteria2Settings, Hysteria2Transport,
};
use dnet_config::reality::{
    RealityClientParams, RealityCredentials, RealityEndpointParams, RealityPublicKey,
    RealitySettings, RealityTransport, TargetDomain, UtlsFingerprint, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_config::{ActiveEndpointBypass, PrimaryTransport};
use dnet_core::endpoint::EndpointAddress;
use dnet_core::ids::ProfileId;
use dnet_core::probe::{judge, RaceDecision};
use dnet_core::profile::{ConnectionProfile, ProfileKind, ProfileParams};
use dnet_probe::measure::{MeasureConfig, Origin};
use dnet_probe::runner::{free_loopback_ports, ProbeJob, Prober, READY_TIMEOUT};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2Client {
    server_port: u16,
    server_name: String,
    spki_sha256_hex: String,
    auth_password: String,
    obfs_password: String,
    origin_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityClient {
    server_port: u16,
    target_domain: String,
    public_key: String,
    short_id: String,
    uuid: String,
    #[allow(dead_code)]
    flow: String,
    #[allow(dead_code)]
    origin_url: String,
}

fn hex32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let mut endpoint = "127.0.0.1".to_string();
    let mut bytes: u64 = 2_000_000;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--endpoint" => endpoint = value()?,
            "--bytes" => bytes = value()?.parse()?,
            other => bail!("unknown argument {other:?}"),
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let state = root.join("testing/harness/.state");
    let core = root.join("vendor/primary-core/primary-core.exe");
    if !core.is_file() {
        bail!("vendored core missing: run `cargo xtask fetch-vendor`");
    }
    let hy2: Hy2Client = serde_json::from_slice(&std::fs::read(state.join("hy2-client.json"))?)
        .context("hy2-client.json (is the harness endpoint up?)")?;
    let reality: RealityClient =
        serde_json::from_slice(&std::fs::read(state.join("reality-client.json"))?)
            .context("reality-client.json (is the harness endpoint up?)")?;

    let hy2_transport = Hysteria2Transport {
        settings: Hysteria2Settings {
            client: Hysteria2ClientParams::default(),
            endpoint: Hysteria2EndpointParams {
                obfs: Hysteria2Obfs::Salamander,
                trust: ServerTrust::PinnedPublicKey {
                    server_name: hy2.server_name.clone(),
                    spki_sha256: hex32(&hy2.spki_sha256_hex)?,
                },
            },
        },
        credentials: Hysteria2Credentials {
            auth_password: Secret::new(hy2.auth_password.clone()),
            obfs_password: Secret::new(hy2.obfs_password.clone()),
        },
    };
    let reality_transport = RealityTransport {
        settings: RealitySettings {
            client: RealityClientParams {
                utls_fingerprint: UtlsFingerprint::Chrome,
            },
            endpoint: RealityEndpointParams {
                target_domain: TargetDomain::parse(&reality.target_domain)?,
                public_key: RealityPublicKey::parse(&reality.public_key)?,
                flow: VlessFlow::Vision,
            },
        },
        credentials: RealityCredentials {
            uuid: Secret::new(reality.uuid.clone()),
            short_id: Secret::new(reality.short_id.clone()),
        },
    };

    let work_dir = root.join("target/probe-work");
    std::fs::create_dir_all(&work_dir)?;

    let ports = free_loopback_ports(2)?;
    let mut jobs = Vec::new();
    for ((id, kind, port, transport), socks_port) in [
        (
            "hy2-default",
            ProfileKind::Hysteria2,
            hy2.server_port,
            PrimaryTransport::Hysteria2(&hy2_transport),
        ),
        (
            "reality-default",
            ProfileKind::VlessReality,
            reality.server_port,
            PrimaryTransport::VlessReality(&reality_transport),
        ),
    ]
    .into_iter()
    .zip(ports)
    {
        let profile = ConnectionProfile::new(ProfileId::new(id), kind, ProfileParams::new());
        let address = EndpointAddress::new(&endpoint, port)?;
        jobs.push(ProbeJob::new(
            profile,
            &ActiveEndpointBypass::new(&address),
            transport,
            socks_port,
        )?);
    }

    let prober = Prober {
        core_exe: core,
        work_dir,
        origin: Origin::parse(&hy2.origin_url)?,
        measure: MeasureConfig {
            connect_timeout: Duration::from_secs(8),
            transfer_timeout: Duration::from_secs(12),
            bytes,
        },
        ready_timeout: READY_TIMEOUT,
    };
    // Anything a crashed earlier run left behind holds credentials.
    prober.sweep_stale();

    println!(
        "endpoint {endpoint}, origin {}, {bytes} bytes\n",
        hy2.origin_url
    );
    println!("-- each profile alone");
    for job in jobs.clone() {
        let id = job.profile().id().to_string();
        let started = std::time::Instant::now();
        let probe = prober.probe_one(job).await;
        println!(
            "{id:16} {:>6.1}s  {probe:?}\n{:16}          => {:?}",
            started.elapsed().as_secs_f64(),
            "",
            judge(probe)
        );
    }

    println!("\n-- the race");
    let started = std::time::Instant::now();
    let report = prober.race(jobs).await?;
    println!(
        "decided after {:.1}s: {:?}",
        started.elapsed().as_secs_f64(),
        report.decision
    );
    for (id, probe, at) in &report.results {
        println!("  {id} reported at {:.1}s: {probe:?}", at.as_secs_f64());
    }
    // One line for scripts to read: `testing/harness/Invoke-Race.ps1` matches on it.
    println!(
        "RESULT {}",
        match &report.decision {
            RaceDecision::Selected { profile, .. } => format!("selected {profile}"),
            RaceDecision::NoneUsable => "none".to_string(),
            RaceDecision::Pending => "pending".to_string(),
        }
    );
    Ok(())
}
