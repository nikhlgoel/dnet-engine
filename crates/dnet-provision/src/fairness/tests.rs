// SPDX-License-Identifier: GPL-3.0-or-later
//! T189 — what the fairness scripts say and do. The helper is run for real, against stand-ins for `ip` and `tc`
//! that record what they were asked, so what reaches the server's queue is exactly what is asserted here.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::*;

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
fn only_a_sensible_speed_makes_a_script() {
    for bad in [0, MAX_MBIT + 1, u32::MAX] {
        assert_eq!(fairness_script(bad), Err(FairnessError::Rate), "{bad}");
    }
    for good in [MIN_MBIT, 45, 1000, MAX_MBIT] {
        assert!(fairness_script(good).is_ok(), "{good}");
    }
}

#[test]
fn every_script_and_the_helper_are_valid_shell() {
    let Some(shell) = shell() else {
        eprintln!("SKIPPED: no shell on this machine");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let scripts = [
        fairness_script(45).unwrap(),
        fairness_off_script(),
        helper(),
    ];
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
}

#[test]
fn the_speed_is_the_only_thing_that_varies_and_it_is_only_digits() {
    let a = fairness_script(45).unwrap();
    let b = fairness_script(46).unwrap();
    let differing: Vec<_> = a.lines().zip(b.lines()).filter(|(x, y)| x != y).collect();
    assert_eq!(differing.len(), 2, "{differing:?}");
    for (x, y) in differing {
        assert!(x.contains("45") && y.contains("46"), "{x} / {y}");
    }
    assert_eq!(a.lines().count(), b.lines().count());
}

#[test]
fn a_script_touches_only_the_cards_queue_and_its_own_service() {
    for text in [fairness_script(45).unwrap(), fairness_off_script()] {
        for forbidden in [
            "iptables",
            "ip6tables",
            "nft ",
            "ufw",
            "ip route add",
            "ip route del",
            "ip rule",
            "ip link",
            "ip addr",
            "sysctl",
            "curl",
            "wget",
            "ssh",
            "primary-core",
            "/var/lib/dnet",
            "server.json",
        ] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} is in a fairness script"
            );
        }
        assert!(text.contains("run this as root"));
        assert!(text.contains("the tc program is needed"));
    }
    // It says how to undo it.
    let on = fairness_script(45).unwrap();
    assert!(on.contains("dnet-fairness.service"));
    assert!(on.contains("Turn it off again"));
    let off = fairness_off_script();
    assert!(off.contains("disable --now dnet-fairness.service"));
    assert!(off.contains("dnet-fairness\" remove"));
}

#[test]
fn it_starts_again_after_a_restart_and_waits_for_the_network() {
    let on = fairness_script(45).unwrap();
    assert!(on.contains("WantedBy=multi-user.target"));
    assert!(on.contains("After=network-online.target"));
    assert!(on.contains("RemainAfterExit=yes"));
    assert!(on.contains("ExecStart=/opt/dnet/bin/dnet-fairness apply 45\n"));
    assert!(on.contains("ExecStop=/opt/dnet/bin/dnet-fairness remove\n"));
}

// ------------------------------------------------------------------ the helper, run for real

/// A directory with stand-ins for `ip` and `tc`: `ip` says the default route leaves through `nic`, and `tc`
/// records every call and answers `show` from a state file.
struct Fake {
    dir: tempfile::TempDir,
    shell: &'static str,
}

impl Fake {
    fn new(nic: &str) -> Option<Self> {
        let shell = shell()?;
        let dir = tempfile::tempdir().unwrap();
        let fake = Self { dir, shell };
        fake.tool(
            "ip",
            &format!(
                "if [ -n '{nic}' ]; then echo 'default via 10.0.0.1 dev {nic} proto dhcp'; fi"
            ),
        );
        fake.tool(
            "tc",
            &format!(
                "echo \"$*\" >> '{log}'\n\
                 if [ \"$1 $2\" = 'qdisc show' ]; then cat '{state}' 2>/dev/null || true; fi\n\
                 if [ \"$1 $2\" = 'qdisc replace' ]; then echo 'qdisc htb 1: root refcnt 2' > '{state}'; fi\n\
                 if [ \"$1 $2\" = 'qdisc del' ]; then rm -f '{state}'; fi",
                log = fake.slashed(&fake.log()),
                state = fake.slashed(&fake.state()),
            ),
        );
        std::fs::write(fake.dir.path().join("helper.sh"), helper()).unwrap();
        Some(fake)
    }

    /// A path as the shell wants it: forward slashes, so a Windows shell reads it too.
    fn slashed(&self, path: &Path) -> String {
        path.display().to_string().replace('\\', "/")
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("tc.log")
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("tc.state")
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Run the helper with the stand-ins first on the path.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let path = std::env::var("PATH").unwrap_or_default();
        let sep = if cfg!(windows) { ";" } else { ":" };
        let out = Command::new(self.shell)
            .arg(self.dir.path().join("helper.sh"))
            .args(args)
            .env("PATH", format!("{}{sep}{path}", self.dir.path().display()))
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.log())
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim_end_matches('\r').to_owned())
            .collect()
    }
}

macro_rules! fake {
    ($nic:expr) => {
        match Fake::new($nic) {
            Some(f) => f,
            None => {
                eprintln!("SKIPPED: no shell on this machine");
                return;
            }
        }
    };
}

#[test]
fn applying_shapes_the_default_card_to_the_speed_and_shares_it_by_connection() {
    let f = fake!("ens3");
    let (code, out, err) = f.run(&["apply", "45"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("applied: ens3, 45 megabits"), "{out}");
    assert_eq!(
        f.calls(),
        [
            "qdisc replace dev ens3 root handle 1: htb default 10",
            "class replace dev ens3 parent 1: classid 1:10 htb rate 45mbit ceil 45mbit quantum 1514",
            "qdisc replace dev ens3 parent 1:10 handle 10: fq_codel",
        ]
    );
}

#[test]
fn a_speed_that_is_not_a_plain_number_in_range_changes_nothing() {
    let f = fake!("ens3");
    for bad in [
        "",
        "0",
        "10001",
        "-5",
        "4.5",
        "45; rm -rf /",
        "$(id)",
        "`id`",
        "45 ",
        "999999",
        "\u{ff10}\u{ff15}",
        "abc",
    ] {
        let (code, _, err) = f.run(&["apply", bad]);
        assert_eq!(code, 2, "{bad:?}: {err}");
    }
    let (code, _, _) = f.run(&["apply"]);
    assert_eq!(code, 2);
    let (code, _, _) = f.run(&[]);
    assert_eq!(code, 2);
    let (code, _, _) = f.run(&["something-else"]);
    assert_eq!(code, 2);
    assert!(f.calls().is_empty(), "tc was asked: {:?}", f.calls());
}

#[test]
fn no_default_route_or_a_card_with_an_odd_name_changes_nothing() {
    for nic in ["", "eth0;reboot", "bad|name", "$(id)"] {
        let f = fake!(nic);
        let (code, _, err) = f.run(&["apply", "45"]);
        assert_eq!(code, 3, "{nic:?}: {err}");
        assert!(f.calls().is_empty(), "{nic:?}: {:?}", f.calls());
    }
}

#[test]
fn removing_takes_away_only_what_the_helper_put_there() {
    let f = fake!("ens3");
    // Nothing of ours: nothing is deleted.
    let (code, out, _) = f.run(&["remove"]);
    assert_eq!(code, 0);
    assert!(out.contains("nothing to remove"), "{out}");
    assert!(!f.calls().iter().any(|c| c.starts_with("qdisc del")));
    // After applying, it is.
    f.run(&["apply", "45"]);
    assert!(f.state().exists());
    let (code, out, _) = f.run(&["remove"]);
    assert_eq!(code, 0);
    assert!(out.contains("removed: ens3"), "{out}");
    assert!(f.calls().iter().any(|c| c == "qdisc del dev ens3 root"));
    assert!(!f.state().exists());
}

#[test]
fn removing_without_a_card_is_not_an_error_so_a_shutdown_never_hangs_on_it() {
    let f = fake!("");
    let (code, _, _) = f.run(&["remove"]);
    assert_eq!(code, 0);
}
