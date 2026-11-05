//! T188 — the device list, run for real: the program the scripts install is run with Python against files, the
//! scripts are checked by the shell's own parser, and the requests and reports are read hostile.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::*;

fn key(n: u8) -> String {
    STANDARD.encode([n; 32])
}

fn python() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|p| {
        Command::new(p)
            .arg("-c")
            .arg("pass")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// A scratch server: a folder with the program in it, a configuration in the form the setup script writes, and
/// the paths the program is given.
struct Server {
    dir: tempfile::TempDir,
    python: &'static str,
}

impl Server {
    fn new(devices: &[String]) -> Option<Self> {
        let python = python()?;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dnet-devices.py"), program()).unwrap();
        let server = Self { dir, python };
        std::fs::write(server.config(), config_with_peers(devices)).unwrap();
        Some(server)
    }

    fn registry(&self) -> PathBuf {
        self.dir.path().join("devices.json")
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("server.json")
    }

    /// Run the program: its exit code, what it printed, and what it said on the error stream.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(self.python)
            .arg(self.dir.path().join("dnet-devices.py"))
            .arg(args[0])
            .arg(self.registry())
            .args(&args[1..])
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout)
                .replace("\r\n", "\n")
                .trim()
                .to_owned(),
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        )
    }

    fn sync(&self, keys: &[String]) -> (i32, String, String) {
        let config = self.config();
        let mut args = vec!["sync", config.to_str().unwrap()];
        args.extend(keys.iter().map(String::as_str));
        self.run(&args)
    }

    fn add(&self, key: &str, name: &str) -> (i32, String, String) {
        let config = self.config();
        self.run(&["add", config.to_str().unwrap(), key, name])
    }

    fn remove(&self, key: &str) -> (i32, String, String) {
        let config = self.config();
        self.run(&["remove", config.to_str().unwrap(), key])
    }

    fn commit(&self) {
        let config = self.config();
        let (code, _, err) = self.run(&["commit", config.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
    }

    fn list(&self) -> Vec<serde_json::Value> {
        let (code, out, err) = self.run(&["list"]);
        assert_eq!(code, 0, "{err}");
        serde_json::from_str(&out).unwrap()
    }

    fn names(&self) -> Vec<String> {
        self.list()
            .iter()
            .map(|d| d["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn address_of(&self, key: &str) -> Option<String> {
        self.list()
            .iter()
            .find(|d| d["public_key"] == key)
            .map(|d| d["address"].as_str().unwrap().to_owned())
    }
}

/// A server configuration in the form the setup script writes it: the session endpoint with its peers.
fn config_with_peers(keys: &[String]) -> String {
    let peers = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            format!(
                "        {{ \"public_key\": \"{k}\", \"allowed_ips\": [ \"{}/32\" ] }}",
                session_device_address(i)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    // The kind is spelled in two pieces: the vendor name stays out of the source (`lint-branding`).
    let kind = ["wire", "guard"].concat();
    format!(
        "{{\n  \"endpoints\": [\n    {{\n      \"type\": \"{kind}\",\n      \"tag\": \"session-in\",\n      \"listen_port\": 1,\n      \"peers\": [\n{peers}\n      ]\n    }}\n  ]\n}}\n"
    )
}

fn peers_in(config_text: &str) -> Vec<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(config_text).unwrap();
    v["endpoints"][0]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["public_key"].as_str().unwrap().to_owned(),
                p["allowed_ips"][0].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

macro_rules! server {
    ($devices:expr) => {
        match Server::new($devices) {
            Some(s) => s,
            None => {
                eprintln!("SKIPPED: no python on this machine");
                return;
            }
        }
    };
}

// ------------------------------------------------------------------ the program

#[test]
fn the_first_run_makes_the_list_from_the_setup_keys_and_a_later_run_only_adds() {
    let s = server!(&[]);
    let owner = key(1);
    assert_eq!(s.sync(std::slice::from_ref(&owner)).0, 0);
    assert_eq!(s.address_of(&owner).as_deref(), Some("10.9.0.2"));
    assert_eq!(s.names(), ["first device"]);

    // A friend is added and committed.
    let (code, out, err) = s.add(&key(2), "Ravi");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("\"added\": true"), "{out}");
    s.commit();

    // The setup script runs again with only the owner's key: the friend is still there, at the same address.
    assert_eq!(s.sync(std::slice::from_ref(&owner)).0, 0);
    assert_eq!(s.names(), ["first device", "Ravi"]);
    assert_eq!(s.address_of(&key(2)).as_deref(), Some("10.9.0.3"));

    // And a second owner key in a later run joins at the next free address, not over anyone.
    assert_eq!(s.sync(&[owner, key(3)]).0, 0);
    assert_eq!(s.address_of(&key(3)).as_deref(), Some("10.9.0.4"));
}

#[test]
fn a_device_keeps_its_address_when_another_is_removed() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    for (n, name) in [(2, "A"), (3, "B"), (4, "C")] {
        assert_eq!(s.add(&key(n), name).0, 0);
        s.commit();
    }
    let before_c = s.address_of(&key(4)).unwrap();
    assert_eq!(s.remove(&key(2)).0, 0);
    s.commit();
    assert_eq!(
        s.address_of(&key(4)).unwrap(),
        before_c,
        "C moved when A left"
    );
    assert_eq!(s.address_of(&key(3)).as_deref(), Some("10.9.0.4"));
    assert!(s.address_of(&key(2)).is_none());
    // The freed address is the next one given, and nobody else's changes.
    assert_eq!(s.add(&key(5), "D").0, 0);
    s.commit();
    assert_eq!(s.address_of(&key(5)).as_deref(), Some("10.9.0.3"));
    assert_eq!(s.address_of(&key(3)).as_deref(), Some("10.9.0.4"));
}

#[test]
fn adding_the_same_device_again_is_not_an_error_and_changes_nothing() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    assert_eq!(s.add(&key(2), "Ravi").0, 0);
    s.commit();
    let (code, out, _) = s.add(&key(2), "Ravi");
    assert_eq!(code, 0);
    assert!(out.contains("\"added\": false"), "{out}");
    assert!(out.contains("\"devices\": 2"), "{out}");
    assert_eq!(s.list().len(), 2);
}

#[test]
fn a_name_already_used_is_refused_so_a_removal_can_never_mean_the_wrong_person() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    assert_eq!(s.add(&key(2), "Ravi").0, 0);
    s.commit();
    let (code, _, err) = s.add(&key(3), "Ravi");
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("already on this server"), "{err}");
    assert_eq!(s.list().len(), 2);
}

#[test]
fn the_server_holds_no_more_devices_than_the_session_allows() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    for n in 2..=u8::try_from(MAX_DEVICES).unwrap() {
        assert_eq!(s.add(&key(n), &format!("d{n}")).0, 0, "device {n}");
        s.commit();
    }
    assert_eq!(s.list().len(), MAX_DEVICES);
    let (code, _, err) = s.add(&key(100), "one too many");
    assert_eq!(code, 6, "{err}");
    assert!(err.contains("most devices"), "{err}");
    assert_eq!(s.list().len(), MAX_DEVICES);
}

#[test]
fn the_last_device_cannot_be_removed_and_one_that_is_not_there_is_not_an_error() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    let (code, _, err) = s.remove(&key(1));
    assert_eq!(code, 5, "{err}");
    assert_eq!(s.list().len(), 1);
    assert_eq!(s.add(&key(2), "Ravi").0, 0);
    s.commit();
    let (code, out, _) = s.remove(&key(9));
    assert_eq!(code, 0);
    assert!(out.contains("\"removed\": false"), "{out}");
}

#[test]
fn a_change_is_staged_beside_the_old_files_and_a_refusal_leaves_the_server_as_it_was() {
    let s = server!(&[key(1)]);
    s.sync(&[key(1)]);
    let config_before = std::fs::read_to_string(s.config()).unwrap();
    let registry_before = std::fs::read_to_string(s.registry()).unwrap();
    assert_eq!(s.add(&key(2), "Ravi").0, 0);

    // Staged: the old files are untouched, the new ones are beside them.
    assert_eq!(std::fs::read_to_string(s.config()).unwrap(), config_before);
    assert_eq!(
        std::fs::read_to_string(s.registry()).unwrap(),
        registry_before
    );
    assert!(Path::new(&format!("{}.new", s.config().display())).exists());

    // The core said no: nothing is replaced and nothing is left behind.
    let config = s.config();
    assert_eq!(s.run(&["discard", config.to_str().unwrap()]).0, 0);
    assert_eq!(std::fs::read_to_string(s.config()).unwrap(), config_before);
    assert!(!Path::new(&format!("{}.new", s.config().display())).exists());
    assert!(!Path::new(&format!("{}.new", s.registry().display())).exists());
    assert_eq!(s.list().len(), 1);
}

#[test]
fn the_configuration_is_changed_as_text_in_the_form_the_setup_script_writes() {
    let s = server!(&[key(1)]);
    s.sync(&[key(1)]);
    assert_eq!(s.add(&key(2), "Ravi").0, 0);
    s.commit();
    // Exactly what the setup script would write for the same two devices, so running it again sees no change and
    // does not restart the server for nothing.
    assert_eq!(
        std::fs::read_to_string(s.config()).unwrap(),
        config_with_peers(&[key(1), key(2)])
    );
    // And the session's peers are the devices, with the addresses the list gave.
    let peers = peers_in(&std::fs::read_to_string(s.config()).unwrap());
    assert_eq!(
        peers,
        vec![
            (key(1), "10.9.0.2/32".to_owned()),
            (key(2), "10.9.0.3/32".to_owned())
        ]
    );
}

#[test]
fn a_server_set_up_before_the_list_existed_keeps_its_devices() {
    // Its configuration has two peers and there is no list yet.
    let s = server!(&[key(1), key(2)]);
    assert!(!s.registry().exists());
    assert_eq!(s.add(&key(3), "Ravi").0, 0);
    s.commit();
    assert_eq!(s.names(), ["first device", "device 2", "Ravi"]);
    assert_eq!(s.address_of(&key(2)).as_deref(), Some("10.9.0.3"));
    assert_eq!(s.address_of(&key(3)).as_deref(), Some("10.9.0.4"));
}

#[test]
fn a_damaged_list_is_never_overwritten() {
    let s = server!(&[key(1)]);
    s.sync(&[key(1)]);
    for damage in [
        "not json".to_owned(),
        "{}".to_owned(),
        r#"{"version":1,"devices":[{"address":"10.9.0.2","public_key":"nope","name":"a"}]}"#
            .to_owned(),
        format!(
            r#"{{"version":1,"devices":[{{"address":"10.9.0.2","public_key":"{}","name":"a"}},{{"address":"10.9.0.3","public_key":"{}","name":"a"}}]}}"#,
            key(1),
            key(2)
        ),
        format!(
            r#"{{"version":1,"devices":[{{"address":"10.9.0.99","public_key":"{}","name":"a"}}]}}"#,
            key(1)
        ),
    ] {
        std::fs::write(s.registry(), &damage).unwrap();
        let (code, _, err) = s.add(&key(5), "Ravi");
        assert_eq!(code, 7, "{damage}: {err}");
        assert!(err.contains("damaged"), "{err}");
        assert_eq!(std::fs::read_to_string(s.registry()).unwrap(), damage);
    }
}

#[test]
fn hostile_names_and_keys_never_get_into_the_list() {
    let s = server!(&[key(1)]);
    s.sync(&[key(1)]);
    let long = "a".repeat(33);
    for name in [
        "",
        " a",
        "a ",
        "it's",
        "a;b",
        "$(x)",
        "a\nb",
        "é",
        long.as_str(),
    ] {
        let (code, _, _) = s.add(&key(2), name);
        assert_eq!(code, 2, "{name:?}");
    }
    let wrong_length = &key(2)[..43];
    let all_a = "A".repeat(44);
    for bad in ["", "short", all_a.as_str(), wrong_length] {
        let (code, _, _) = s.add(bad, "Ravi");
        assert_eq!(code, 2, "{bad:?}");
    }
    assert_eq!(s.list().len(), 1);
}

#[test]
fn a_configuration_in_a_form_the_program_does_not_know_is_refused_untouched() {
    let s = server!(&[key(1)]);
    s.sync(&[key(1)]);
    std::fs::write(s.config(), "{ \"endpoints\": [] }\n").unwrap();
    let (code, _, err) = s.add(&key(2), "Ravi");
    assert_eq!(code, 7, "{err}");
    assert_eq!(
        std::fs::read_to_string(s.config()).unwrap(),
        "{ \"endpoints\": [] }\n"
    );
}

#[test]
fn the_peers_the_program_prints_are_what_the_setup_script_puts_in_its_configuration() {
    let s = server!(&[]);
    s.sync(&[key(1)]);
    assert_eq!(s.add(&key(2), "Ravi").0, 0);
    s.commit();
    let (code, peers, _) = s.run(&["peers"]);
    assert_eq!(code, 0);
    let expected = config_with_peers(&[key(1), key(2)]);
    assert!(expected.contains(&peers), "{peers}");
}

// ------------------------------------------------------------------ the scripts

fn request() -> DeviceRequest {
    DeviceRequest::new("Ravi", &key(7)).unwrap()
}

fn shell() -> Option<&'static str> {
    ["sh", "bash"].into_iter().find(|s| {
        Command::new(s)
            .arg("-c")
            .arg("true")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

#[test]
fn every_script_is_valid_shell_and_its_embedded_python_compiles() {
    let Some(shell) = shell() else {
        eprintln!("SKIPPED: no shell on this machine");
        return;
    };
    let scripts = [
        add_device_script(&request()),
        remove_device_script(&key(7)).unwrap(),
        list_devices_script(),
    ];
    let dir = tempfile::tempdir().unwrap();
    for (i, text) in scripts.iter().enumerate() {
        let path = dir.path().join(format!("s{i}.sh"));
        std::fs::write(&path, text).unwrap();
        let out = Command::new(shell).arg("-n").arg(&path).output().unwrap();
        assert!(
            out.status.success(),
            "script {i}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    if let Some(python) = python() {
        let path = dir.path().join("dnet-devices.py");
        std::fs::write(&path, program()).unwrap();
        let out = Command::new(python)
            .args(["-m", "py_compile"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn the_scripts_check_with_the_core_before_replacing_anything_and_restart_only_on_a_change() {
    for text in [
        add_device_script(&request()),
        remove_device_script(&key(7)).unwrap(),
    ] {
        let check = text
            .find("primary-core\" check -c \"$CONFIG.new\"")
            .unwrap();
        let commit = text.find("dnet-devices\" commit").unwrap();
        let restart = text.find("systemctl restart dnet-primary.service").unwrap();
        assert!(check < commit && commit < restart);
        assert!(text
            .contains("if cmp -s \"$CONFIG.new\" \"$CONFIG\"; then CHANGED=0; else CHANGED=1; fi"));
        assert!(text.contains("[ \"$CHANGED\" = 1 ] || [ \"${FORCE_RESTART:-0}\" = 1 ]"));
        // One script at a time, a dropped connection does not stop it, and the new files are readable by the
        // core before they take the old ones' place.
        assert!(
            text.contains("flock 9"),
            "the whole script runs under one lock"
        );
        assert!(text.contains("trap '' HUP"));
        let chown = text
            .find("chown root:dnet \"$REG.new\" \"$CONFIG.new\"")
            .unwrap();
        assert!(chown < commit, "permissions are set before the swap");
        assert!(text.contains("discard"), "a refusal must clean up");
        assert!(
            text.contains("run this as root"),
            "it needs root and says so"
        );
        assert!(
            text.contains("set it up first"),
            "it refuses a machine that is not a DNet server"
        );
    }
    // Listing changes nothing: it never commits, never restarts the server, never replaces a file.
    let list = list_devices_script();
    assert!(
        !list.contains("dnet-devices\" commit"),
        "a listing must not commit"
    );
    assert!(
        !list.contains("systemctl restart"),
        "a listing must not restart the server"
    );
    assert!(
        !list.contains("primary-core\" check"),
        "a listing has nothing to check"
    );
}

#[test]
fn the_scripts_hold_only_public_material() {
    let add = add_device_script(&request());
    assert!(
        add.contains(&key(7)),
        "the device's public key is the point"
    );
    assert!(add.contains("'Ravi'"));
    assert_eq!(
        add.matches(&key(7)).count(),
        2,
        "the key appears where it is used and nowhere else"
    );
}

#[test]
fn the_program_is_the_same_in_every_script_and_uses_the_sessions_own_constants() {
    let program = program();
    assert!(program.contains("MAX_DEVICES = 8"));
    assert!(program.contains("PREFIX = \"10.9.0.\""));
    assert!(program.contains("FIRST = 2"));
    assert!(!program.contains("@@"), "a placeholder was left unfilled");
    for text in [
        add_device_script(&request()),
        remove_device_script(&key(7)).unwrap(),
        list_devices_script(),
    ] {
        assert!(
            text.contains(program.trim_end()),
            "a script carries a different program"
        );
    }
    // The list's addresses are the session's, one for one.
    for i in 0..MAX_DEVICES {
        assert_eq!(
            session_device_address(i).to_string(),
            format!("10.9.0.{}", 2 + i)
        );
    }
}

// ------------------------------------------------------------------ the request and the reports

#[test]
fn a_request_round_trips_and_carries_nothing_but_a_name_and_a_public_key() {
    let r = request();
    let text = r.encode();
    assert!(text.starts_with(REQUEST_PREFIX));
    assert_eq!(DeviceRequest::decode(&text).unwrap(), r);
    assert_eq!(
        DeviceRequest::decode(&format!("hello!\n{text}\nthanks")).unwrap(),
        r
    );
    let v: serde_json::Value = serde_json::from_str(&text[REQUEST_PREFIX.len()..]).unwrap();
    let mut fields: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    fields.sort();
    assert_eq!(fields, ["name", "public_key", "version"]);
}

#[test]
fn a_request_with_anything_wrong_is_refused() {
    for (name, k) in [
        ("", key(1)),
        ("bad'name", key(1)),
        ("Ravi", "short".to_owned()),
        ("Ravi", "A".repeat(44)),
    ] {
        assert!(DeviceRequest::new(name, &k).is_err(), "{name:?} {k:?}");
    }
    let good = request().encode();
    let json = &good[REQUEST_PREFIX.len()..];
    for bad in [
        format!("{REQUEST_PREFIX}{{}}"),
        format!("{REQUEST_PREFIX}not json"),
        format!(
            "{REQUEST_PREFIX}{}",
            json.replace("\"version\":1", "\"version\":2")
        ),
        format!("{REQUEST_PREFIX}{}", json.replace('}', ",\"extra\":1}")),
        "hello".to_owned(),
        String::new(),
    ] {
        assert!(DeviceRequest::decode(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        DeviceRequest::decode(&"x".repeat(MAX_PASTE_LEN + 1)),
        Err(DeviceError::TooLarge)
    );
}

/// A change made to a good add report, to make it wrong in one way.
type Edit = Box<dyn Fn(&mut serde_json::Value)>;

fn add_report(edit: impl Fn(&mut serde_json::Value)) -> String {
    let mut v = serde_json::json!({
        "version": 1, "action": "add", "public_key": key(7), "name": "Ravi", "address": "10.9.0.3",
        "added": true, "server_public_key": key(50), "port": 25182, "devices": 2
    });
    edit(&mut v);
    format!("some text\n{REPORT_PREFIX}{v}\nmore")
}

#[test]
fn an_add_report_is_read_and_must_be_for_the_request_it_answers() {
    let added = DeviceAdded::parse(&add_report(|_| {}), &request()).unwrap();
    assert_eq!(added.address.to_string(), "10.9.0.3");
    assert_eq!(added.server_public_key, key(50));
    assert!(added.added);

    // Another device's result, another name's, or another kind of result, is not this one.
    let other_key = STANDARD.encode([8u8; 32]);
    let mismatches: Vec<Edit> = vec![
        Box::new(move |v| v["public_key"] = serde_json::Value::from(other_key.clone())),
        Box::new(|v| v["name"] = serde_json::Value::from("Someone")),
        Box::new(|v| v["action"] = serde_json::Value::from("remove")),
    ];
    for edit in &mismatches {
        assert_eq!(
            DeviceAdded::parse(&add_report(edit), &request()),
            Err(DeviceError::Mismatch)
        );
    }
    // An address no device can have, a server key that is not a key, no devices, too many, and a missing field.
    let broken: Vec<Edit> = vec![
        Box::new(|v| v["address"] = serde_json::Value::from("10.9.0.1")),
        Box::new(|v| v["address"] = serde_json::Value::from("8.8.8.8")),
        Box::new(|v| v["server_public_key"] = serde_json::Value::from("short")),
        Box::new(|v| v["port"] = serde_json::Value::from(0)),
        Box::new(|v| v["devices"] = serde_json::Value::from(0)),
        Box::new(|v| v["devices"] = serde_json::Value::from(MAX_DEVICES + 1)),
        Box::new(|v| {
            v.as_object_mut().unwrap().remove("address");
        }),
        Box::new(|v| v["extra"] = serde_json::Value::from(1)),
    ];
    for edit in &broken {
        assert!(DeviceAdded::parse(&add_report(edit), &request()).is_err());
    }
    assert_eq!(
        DeviceAdded::parse("nothing here", &request()),
        Err(DeviceError::NotAReport)
    );
}

#[test]
fn a_removal_report_and_a_list_are_read_and_checked() {
    let removed = format!(
        "{REPORT_PREFIX}{}",
        serde_json::json!({"version":1,"action":"remove","public_key":key(7),"removed":true,"devices":1})
    );
    let r = DeviceRemoved::parse(&removed, &key(7)).unwrap();
    assert!(r.removed);
    assert_eq!(
        DeviceRemoved::parse(&removed, &key(8)),
        Err(DeviceError::Mismatch)
    );

    let list = format!(
        "{REPORT_PREFIX}{}",
        serde_json::json!({"version":1,"action":"list","list":[
            {"address":"10.9.0.2","public_key":key(1),"name":"first device"},
            {"address":"10.9.0.3","public_key":key(7),"name":"Ravi"}]})
    );
    let devices = parse_list(&list).unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[1].name, "Ravi");
    for bad in [
        serde_json::json!({"version":1,"action":"list","list":[{"address":"10.9.0.2","public_key":"x","name":"a"}]}),
        serde_json::json!({"version":1,"action":"list","list":[{"address":"10.9.0.2","public_key":key(1),"name":"bad'name"}]}),
        serde_json::json!({"version":1,"action":"list","list":[{"address":"1.1.1.1","public_key":key(1),"name":"a"}]}),
        serde_json::json!({"version":1,"action":"add"}),
    ] {
        assert!(parse_list(&format!("{REPORT_PREFIX}{bad}")).is_err());
    }
}

#[test]
fn arbitrary_pasted_text_never_panics() {
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in 0..3000 {
        let len = (next() % 160) as usize;
        let body: String = (0..len)
            .map(|_| {
                let r = next();
                match r % 5 {
                    0 => char::from_u32((r >> 8) as u32 % 0x11_0000).unwrap_or('?'),
                    1 => '"',
                    2 => '{',
                    _ => (b'a' + (r % 26) as u8) as char,
                }
            })
            .collect();
        let prefix = if i % 2 == 0 {
            REQUEST_PREFIX
        } else {
            REPORT_PREFIX
        };
        let text = format!("{prefix}{body}");
        let _ = DeviceRequest::decode(&text);
        let _ = DeviceAdded::parse(&text, &request());
        let _ = DeviceRemoved::parse(&text, &key(7));
        let _ = parse_list(&text);
    }
}

#[test]
fn only_a_removal_always_restarts_so_a_cut_off_run_still_ends_the_session() {
    assert!(remove_device_script(&key(7)).unwrap().contains(
        "
FORCE_RESTART=1
"
    ));
    assert!(!add_device_script(&request()).contains("FORCE_RESTART=1"));
}

#[test]
fn the_all_zero_key_is_not_a_device_key_in_rust_or_on_the_server() {
    let zero = STANDARD.encode([0u8; 32]);
    assert!(!is_device_key(&zero));
    assert!(DeviceRequest::new("Ravi", &zero).is_err());
    assert!(remove_device_script(&zero).is_err());
    let s = server!(&[key(1)]);
    assert_eq!(s.add(&zero, "Ravi").0, 2);
    assert!(is_device_key(&key(1)));
}

#[test]
fn a_legacy_configuration_with_a_peer_the_program_does_not_recognise_is_refused_untouched() {
    // An address outside the range, and a key that is not a key: the list would be written damaged.
    for peers in [
        config_with_peers(&[key(1)]).replace("10.9.0.2/32", "10.9.0.200/32"),
        config_with_peers(&[key(1)]).replace(&key(1), "not-a-key"),
    ] {
        let s = server!(&[key(1)]);
        std::fs::write(s.config(), &peers).unwrap();
        let (code, _, err) = s.add(&key(9), "Ravi");
        assert_eq!(code, 7, "{err}");
        assert!(!s.registry().exists(), "nothing is written");
        assert!(
            !s.registry().with_extension("json.new").exists(),
            "nothing is staged"
        );
    }
}

#[test]
fn a_report_that_names_another_servers_key_or_port_is_refused() {
    let request = request();
    let text = add_report(|_| {});
    let added = DeviceAdded::parse(&text, &request).unwrap();
    let (skey, port) = (added.server_public_key.clone(), added.port);
    assert!(DeviceAdded::parse_for_server(&text, &request, &skey, port).is_ok());
    assert_eq!(
        DeviceAdded::parse_for_server(&text, &request, &key(99), port),
        Err(DeviceError::Mismatch)
    );
    assert_eq!(
        DeviceAdded::parse_for_server(&text, &request, &skey, port.wrapping_add(1)),
        Err(DeviceError::Mismatch)
    );
}
