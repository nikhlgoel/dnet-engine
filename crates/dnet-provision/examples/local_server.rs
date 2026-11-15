// SPDX-License-Identifier: GPL-3.0-or-later
//! The lab's two halves of "set up a server", for running the real setup script in a container
//! (`testing/server-lab`, T200). The product does these steps through a provider (T093); here the machine is a
//! container, so the two ends of the flow are driven by hand and everything between them is the product's code.
//!
//! ```text
//! local_server plan        <pins.json> <state-dir> <amd64|arm64> <awg-port> <hy2-port> <reality-port>
//! local_server credentials <state-dir> <report-file> <out-file>
//! local_server script      <state-dir>
//! local_server keepalive   <out-file>
//! local_server test-request <name> <request-out>        (a made-up friend, to try the flow; its key is thrown away)
//! local_server remove-device <request-file> <script-out>  (takes a friend's device off the server again)
//! local_server list-devices <script-out>
//! local_server add-device  <request-file> <script-out>
//! local_server invite      <credentials-file> <request-file> <report-file> <label> <host> <invite-out>
//! ```
//!
//! `add-device` and `invite` are the owner's two halves of "add a friend's device" (T188) for a server whose owner
//! works from a terminal: the friend sends the request their window made; `add-device` writes the script to run on
//! the server; the server prints a report line; `invite` reads it with the product's own parser, checks it against
//! the owner's own credentials for that server, and writes the invite to send back. The friend's private key is never
//! seen here.
//!
//! `script` writes `setup.sh` again from the saved plan, with the same keys, when the script's text has changed (it is
//! safe to run the script again on a server that is already set up).
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
        Some("script") if args.len() == 2 => rescript(&args[1..]),
        Some("keepalive") if args.len() == 2 => keepalive(&args[1]),
        Some("add-device") if args.len() == 3 => add_device(&args[1..]),
        Some("test-request") if args.len() == 3 => test_request(&args[1..]),
        Some("remove-device") if args.len() == 3 => remove_device(&args[1..]),
        Some("list-devices") if args.len() == 2 => {
            std::fs::write(&args[1], dnet_provision::devices::list_devices_script()).map_err(|e| e.to_string())
        }
        Some("invite") if args.len() == 7 => invite(&args[1..]),
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

/// The keepalive script the product installs as a stage of its own provisioning (T094), for a server made by hand: a
/// burst of idle-priority work about a tenth of the time, so a free machine that carries little is not reclaimed as idle.
fn keepalive(out: &str) -> Result<(), String> {
    let plan = dnet_provision::keepalive::KeepalivePlan::default();
    std::fs::write(out, dnet_provision::keepalive::script(&plan)).map_err(|e| e.to_string())
}

/// A request from a made-up device, to try the flow end to end. Its private key is dropped at once.
fn test_request(args: &[String]) -> Result<(), String> {
    let keys = SessionKeys::generate().map_err(|e| e.to_string())?;
    let request = dnet_provision::devices::DeviceRequest::new(&args[0], keys.public_b64())
        .map_err(|e| e.to_string())?;
    std::fs::write(&args[1], request.encode()).map_err(|e| e.to_string())?;
    println!(
        "wrote a request for a made-up device \"{}\" to {}",
        args[0], args[1]
    );
    Ok(())
}

/// The script that takes a friend's device off the server again, from the request it was added with.
fn remove_device(args: &[String]) -> Result<(), String> {
    let text = std::fs::read_to_string(&args[0]).map_err(|e| format!("request: {e}"))?;
    let request =
        dnet_provision::devices::DeviceRequest::decode(&text).map_err(|e| e.to_string())?;
    let script = dnet_provision::devices::remove_device_script(request.public_key())
        .map_err(|e| e.to_string())?;
    std::fs::write(&args[1], script).map_err(|e| e.to_string())?;
    println!(
        "wrote the script that takes \"{}\" off the server to {}",
        request.name(),
        args[1]
    );
    Ok(())
}

/// The script that adds the friend's device to the server, from the request the friend's window made.
fn add_device(args: &[String]) -> Result<(), String> {
    let text = std::fs::read_to_string(&args[0]).map_err(|e| format!("request: {e}"))?;
    let request =
        dnet_provision::devices::DeviceRequest::decode(&text).map_err(|e| e.to_string())?;
    std::fs::write(
        &args[1],
        dnet_provision::devices::add_device_script(&request),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "wrote the script that adds \"{}\" to {}",
        request.name(),
        args[1]
    );
    Ok(())
}

/// The invite for a device the server has added, from the server's report and the owner's own credentials.
fn invite(args: &[String]) -> Result<(), String> {
    use dnet_config::credentials::EndpointCredentials;
    use dnet_config::invite::Invite;
    use dnet_provision::devices::{DeviceAdded, DeviceRequest};

    let owner = EndpointCredentials::from_plaintext_json(
        &std::fs::read(&args[0]).map_err(|e| format!("credentials: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let request = DeviceRequest::decode(
        &std::fs::read_to_string(&args[1]).map_err(|e| format!("request: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    let report = std::fs::read_to_string(&args[2]).map_err(|e| format!("report: {e}"))?;
    let session = owner
        .session
        .as_ref()
        .ok_or("this server has no session: it cannot take a friend's device")?;
    let added = DeviceAdded::parse_for_server(
        &report,
        &request,
        &session.server_public_key,
        session.session_port,
    )
    .map_err(|e| e.to_string())?;
    let invite = Invite::new(
        &args[3],
        &args[4],
        &owner,
        added.address,
        request.public_key(),
    )
    .map_err(|e| e.to_string())?;
    let text = invite.encode().map_err(|e| e.to_string())?;
    std::fs::write(&args[5], text).map_err(|e| e.to_string())?;
    println!(
        "wrote the invite for \"{}\" (address {} on the server, {} device(s) on it) to {}",
        added.name, added.address, added.devices, args[5]
    );
    Ok(())
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

fn rescript(args: &[String]) -> Result<(), String> {
    let dir = Path::new(&args[0]);
    let saved = load(dir)?;
    let text = script(&saved.plan).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("setup.sh"), text).map_err(|e| e.to_string())?;
    println!(
        "wrote {} again from the saved plan",
        dir.join("setup.sh").display()
    );
    Ok(())
}
