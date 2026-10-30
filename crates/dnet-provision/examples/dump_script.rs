//! Prints the setup script for a given pins file and processor, for checking it by hand on a Linux machine.
//! `cargo run -p dnet-provision --example dump_script -- <server-pins.json> amd64|arm64`
use dnet_config::amneziawg::ObfuscationParams;
use dnet_provision::bootstrap::{script, BootstrapPlan, Ports, ServerArch};
use dnet_provision::client_keys::{random_obfuscation, ClientKeys};
use dnet_provision::server_pins::ServerPins;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pins = ServerPins::parse(&std::fs::read_to_string(&args[0]).unwrap()).expect("pins");
    let arch = if args[1] == "arm64" {
        ServerArch::Arm64
    } else {
        ServerArch::Amd64
    };
    let keys = ClientKeys::generate().expect("keys");
    let obfuscation: ObfuscationParams = random_obfuscation().expect("params");
    let plan = BootstrapPlan {
        cores: pins.cores_for(arch).expect("cores"),
        ports: Ports::default(),
        awg_client_public_hex: keys.public_hex().to_owned(),
        obfuscation,
        hysteria2_server_name: "edge.example.net".to_owned(),
        reality_target: dnet_config::reality::TargetDomain::parse("www.example.com").unwrap(),
    };
    print!("{}", script(&plan).expect("script"));
}
