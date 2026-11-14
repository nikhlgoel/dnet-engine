// SPDX-License-Identifier: GPL-3.0-or-later
//! The lab's two halves of "set up a server", for running the real setup script in a container
//! (`testing/server-lab`, T200). The product does these steps through a provider (T093); here the machine is a
//! container, so the two ends of the flow are driven by hand and everything between them is the product's code.
//!
//! ```text
//! local_server plan        <pins.json> <state-dir> <amd64|arm64> <awg-port> <hy2-port> <reality-port>
//! local_server credentials <state-dir> <report-file> <out-file>
//! ```
//!
//! `plan` makes the client's own keys (they never leave `<state-dir>`), builds the setup script exactly as the
//! product does and writes it to `<state-dir>/setup.sh`, with what `credentials` needs to read the answer. The
//! script is then run on the server, which prints one report line. `credentials` reads that line with the
//! product's own parser, checks it against the plan, and writes the endpoint credentials a client takes with
//! `dnetctl add-endpoint --credentials-file`. **The state directory holds secrets** (test keys of a throwaway lab
//! server); it is under a gitignored folder.

use std::path::Path;

use dnet_config::amneziawg::ObfuscationParams;
use dnet_config::reality::TargetDomain;
use dnet_provision::bootstrap::{
    script, session_measurement_origin, BootstrapPlan, BootstrapReport, Ports, ServerArch,
    SessionPlan,
};
use dnet_provision::client_keys::{random_obfuscation, ClientKeys, SessionKeys};
use dnet_provision::server_pins::ServerPins;
use serde_json::{json, Value};

const STATE_FILE: &str = "lab-plan.json";
const HY2_NAME: &str = "edge.lab.test";
const REALITY_TARGET: &str = "www.example.com";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("plan") if args.len() == 7 => plan(&args[1..]),
        Some("credentials") if args.len() == 4 => credentials(&args[1..]),
        _ => Err(
            "usage:\n  local_server plan <pins.json> <state-dir> <amd64|arm64> <awg-port> <hy2-port> <reality-port>\n  \
             local_server credentials <state-dir> <report-file> <out-file>"
        .to_owned()),
    };
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn arch(text: &str) -> Result<ServerArch, String> {
    match text {
        "amd64" => Ok(ServerArch::Amd64),
        "arm64" => Ok(ServerArch::Arm64),
        other => Err(format!("unknown processor {other:?}")),
    }
}

fn port(text: &str) -> Result<u16, String> {
    text.parse::<u16>()
        .map_err(|e| format!("port {text:?}: {e}"))
}

fn hex_to_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("a key in the state file is not 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// The plan from what `plan` saved, so `credentials` builds the same one.
struct Saved {
    plan: BootstrapPlan,
    keys: ClientKeys,
    session_keys: SessionKeys,
    obfuscation: ObfuscationParams,
}

fn build(
    pins: &ServerPins,
    arch: ServerArch,
    ports: Ports,
    keys: &ClientKeys,
    session_keys: &SessionKeys,
    obfuscation: ObfuscationParams,
) -> Result<BootstrapPlan, String> {
    Ok(BootstrapPlan {
        cores: pins.cores_for(arch).map_err(|e| e.to_string())?,
        ports,
        awg_client_public_hex: keys.public_hex().to_owned(),
        obfuscation,
        hysteria2_server_name: HY2_NAME.to_owned(),
        reality_target: TargetDomain::parse(REALITY_TARGET).map_err(|e| e.to_string())?,
        session: SessionPlan {
            device_public_keys: vec![session_keys.public_b64().to_owned()],
        },
    })
}

fn plan(args: &[String]) -> Result<(), String> {
    let pins = ServerPins::parse(&std::fs::read_to_string(&args[0]).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let dir = Path::new(&args[1]);
    let arch = arch(&args[2])?;
    let ports = Ports {
        amneziawg_udp: port(&args[3])?,
        hysteria2_udp: port(&args[4])?,
        reality_tcp: port(&args[5])?,
    };
    let keys = ClientKeys::generate().map_err(|e| e.to_string())?;
    let session_keys = SessionKeys::generate().map_err(|e| e.to_string())?;
    let obfuscation = random_obfuscation().map_err(|e| e.to_string())?;
    let plan = build(&pins, arch, ports, &keys, &session_keys, obfuscation)?;
    let text = script(&plan).map_err(|e| e.to_string())?;

    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("setup.sh"), text).map_err(|e| e.to_string())?;
    let o = obfuscation;
    let state = json!({
        "pins": args[0],
        "arch": args[2],
        "ports": [ports.amneziawg_udp, ports.hysteria2_udp, ports.reality_tcp],
        "awg_private_hex": keys.private_hex(),
        "session_private_b64": session_keys.private_b64(),
        "obfuscation": [o.jc, o.jmin, o.jmax, o.s1, o.s2, o.h1, o.h2, o.h3, o.h4],
    });
    std::fs::write(dir.join(STATE_FILE), state.to_string()).map_err(|e| e.to_string())?;
    println!("wrote {}", dir.join("setup.sh").display());
    Ok(())
}

fn load(dir: &Path) -> Result<Saved, String> {
    let state: Value = serde_json::from_slice(
        &std::fs::read(dir.join(STATE_FILE)).map_err(|e| format!("{STATE_FILE}: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let text = |key: &str| {
        state[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{STATE_FILE} has no {key}"))
    };
    let pins = ServerPins::parse(
        &std::fs::read_to_string(text("pins")?).map_err(|e| format!("pins: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let ports = state["ports"]
        .as_array()
        .filter(|a| a.len() == 3)
        .ok_or("ports are not three numbers")?;
    let port_at = |i: usize| {
        ports[i]
            .as_u64()
            .map(|p| p as u16)
            .ok_or("a port is not a number")
    };
    let ports = Ports {
        amneziawg_udp: port_at(0)?,
        hysteria2_udp: port_at(1)?,
        reality_tcp: port_at(2)?,
    };
    let keys = ClientKeys::from_private(hex_to_32(&text("awg_private_hex")?)?);
    let session_keys = {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let bytes = STANDARD
            .decode(text("session_private_b64")?)
            .map_err(|e| e.to_string())?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "session key is not 32 bytes")?;
        SessionKeys::from_private(array)
    };
    let n: Vec<u32> = state["obfuscation"]
        .as_array()
        .ok_or("no obfuscation")?
        .iter()
        .map(|v| v.as_u64().map(|x| x as u32).ok_or("obfuscation value"))
        .collect::<Result<_, _>>()?;
    if n.len() != 9 {
        return Err("obfuscation has the wrong number of values".into());
    }
    let obfuscation = ObfuscationParams {
        jc: n[0],
        jmin: n[1],
        jmax: n[2],
        s1: n[3],
        s2: n[4],
        h1: n[5],
        h2: n[6],
        h3: n[7],
        h4: n[8],
    };
    let plan = build(
        &pins,
        arch(&text("arch")?)?,
        ports,
        &keys,
        &session_keys,
        obfuscation,
    )?;
    Ok(Saved {
        plan,
        keys,
        session_keys,
        obfuscation,
    })
}

fn credentials(args: &[String]) -> Result<(), String> {
    let saved = load(Path::new(&args[0]))?;
    let output = std::fs::read_to_string(&args[1]).map_err(|e| format!("report: {e}"))?;
    let report = BootstrapReport::parse(&output).map_err(|e| e.to_string())?;
    report
        .check_against(&saved.plan)
        .map_err(|e| format!("the server's report does not match the plan: {e}"))?;
    let credentials = report.credentials(
        &saved.keys,
        &saved.session_keys,
        saved.obfuscation,
        Some(session_measurement_origin()),
    );
    let json = credentials.to_plaintext_json().map_err(|e| e.to_string())?;
    std::fs::write(&args[2], json).map_err(|e| e.to_string())?;
    println!(
        "wrote credentials for the three methods and the session to {}",
        args[2]
    );
    Ok(())
}
