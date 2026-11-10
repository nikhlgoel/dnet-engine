//! T161 — the lab tool for the guard (ADR-0006 §5a condition 5: nothing goes onto a real machine before a virtual one
//! has run it). Not part of the product: it applies the guard, reads it back and takes it out, on a machine made to be
//! broken, and says what it found.
//!
//!     guard_lab dump    [options]   the rules the plan makes (no change)
//!     guard_lab apply   [options]   put the guard into the firewall (needs an elevated shell)
//!     guard_lab install [options]   the whole path: undo record first, apply, read back and verify
//!     guard_lab replay              replay the undo journal (what start-up recovery does)
//!     guard_lab verify  [options]   read the firewall back and compare it with the plan, both ways
//!     guard_lab status              is the guard's provider in the firewall
//!     guard_lab remove              take the guard out (the same removal `guard-release` will use)
//!
//! Options: `--tunnel-luid N` or `--tunnel-alias NAME`, `--core PATH`, `--service PATH`, `--control-port N`,
//! `--core-sid SID`, `--service-sid SID`. The defaults are the installed layout and the system account.

#[cfg(not(windows))]
fn main() {
    eprintln!("guard_lab runs on Windows only");
}

#[cfg(windows)]
fn main() {
    if let Err(message) = lab::run(std::env::args().skip(1).collect()) {
        eprintln!("guard_lab: {message}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod lab {
    use dnet_core::guard::{describe, local_ranges, verify, Guard, GuardPlan};
    use dnet_core::ids::InterfaceId;
    use dnet_netstate::guard_engine::Engine;
    use dnet_netstate::guard_wfp::{from_wfp, to_wfp, WfpFilter};

    struct Options {
        tunnel_luid: Option<u64>,
        tunnel_alias: Option<String>,
        core: String,
        service: String,
        control_port: u16,
        core_sid: String,
        service_sid: String,
    }

    fn parse(args: &[String]) -> Result<Options, String> {
        let mut o = Options {
            tunnel_luid: None,
            tunnel_alias: None,
            core: r"C:\Program Files\DNet Engine\primary-core.exe".into(),
            service: r"C:\Program Files\DNet Engine\dnetd.exe".into(),
            control_port: 34_567,
            core_sid: "S-1-5-18".into(),
            service_sid: "S-1-5-18".into(),
        };
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let mut value = || {
                it.next()
                    .cloned()
                    .ok_or_else(|| format!("{flag} needs a value"))
            };
            match flag.as_str() {
                "--tunnel-luid" => {
                    o.tunnel_luid = Some(value()?.parse().map_err(|_| "not a number".to_owned())?)
                }
                "--tunnel-alias" => o.tunnel_alias = Some(value()?),
                "--core" => o.core = value()?,
                "--service" => o.service = value()?,
                "--control-port" => {
                    o.control_port = value()?.parse().map_err(|_| "not a port".to_owned())?
                }
                "--core-sid" => o.core_sid = value()?,
                "--service-sid" => o.service_sid = value()?,
                other => return Err(format!("unknown option {other}")),
            }
        }
        Ok(o)
    }

    fn plan(o: &Options) -> Result<GuardPlan, String> {
        let luid = match (&o.tunnel_luid, &o.tunnel_alias) {
            (Some(luid), _) => *luid,
            (None, Some(alias)) => dnet_netstate::adapter::interface_luid(alias)
                .map(|l| unsafe { l.Value })
                .map_err(|e| e.to_string())?,
            // No adapter named: a stand-in the lab can apply (it matches nothing, so the tunnel permit is inert).
            (None, None) => 0x0006_0000_0000_0007,
        };
        Ok(GuardPlan {
            tunnel: InterfaceId::new(luid),
            core_program: o.core.clone(),
            core_user: o.core_sid.clone(),
            service_program: o.service.clone(),
            service_user: o.service_sid.clone(),
            control_port: o.control_port,
            local_ranges: local_ranges(),
        })
    }

    /// The undo journal the lab keeps beside its tools, so a replay can follow a crash of the tool itself.
    fn journal() -> Result<dnet_netstate::undo::UndoRegistry, String> {
        let path = std::path::PathBuf::from(r"C:\lab\undo.json");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        dnet_netstate::undo::UndoRegistry::open(Box::new(dnet_netstate::undo_file::FileStore::new(
            &path,
        )))
        .map_err(|e| e.to_string())
    }

    pub fn run(args: Vec<String>) -> Result<(), String> {
        let Some(command) = args.first().cloned() else {
            return Err("a command: dump, apply, verify, status or remove".into());
        };
        let options = parse(&args[1..])?;
        match command.as_str() {
            "dump" => {
                let guard = Guard::build(&plan(&options)?).map_err(|e| e.to_string())?;
                for f in guard.filters() {
                    println!("{}", describe(f));
                }
                println!("{} rules", guard.filters().len());
            }
            "apply" => {
                let guard = Guard::build(&plan(&options)?).map_err(|e| e.to_string())?;
                let translated: Vec<WfpFilter> = guard
                    .filters()
                    .iter()
                    .map(to_wfp)
                    .collect::<Result<_, _>>()
                    .map_err(|e| e.to_string())?;
                let engine = Engine::open().map_err(|e| e.to_string())?;
                engine.apply(&translated).map_err(|e| e.to_string())?;
                println!("applied {} rules", translated.len());
            }
            "verify" => {
                let plan = plan(&options)?;
                let engine = Engine::open().map_err(|e| e.to_string())?;
                let known = vec![options.core.clone(), options.service.clone()];
                let held = engine.read_back(&known).map_err(|e| e.to_string())?;
                println!(
                    "the firewall holds {} rules under the guard's provider",
                    held.len()
                );
                let mut installed = Vec::new();
                for w in &held {
                    installed.push(from_wfp(w).map_err(|e| format!("{e} ({})", w.name))?);
                }
                let problems = verify(&plan, &installed);
                if problems.is_empty() {
                    println!("VERIFIED: what the firewall holds is exactly what the plan makes");
                } else {
                    for p in &problems {
                        println!("PROBLEM: {p}");
                    }
                    return Err(format!("{} problem(s)", problems.len()));
                }
            }
            "install" => {
                // The whole path the service will take: the undo record first, the rules, then the read-back check.
                let registry = journal()?;
                let count = dnet_netstate::guard_engine::install_guard(&registry, &plan(&options)?)
                    .map_err(|e| e.to_string())?;
                println!("installed: the firewall holds {count} rules, read back and verified");
                println!(
                    "undo journal holds {} record(s)",
                    registry.outstanding().len()
                );
            }
            "replay" => {
                // What start-up recovery does with the journal after a crash.
                let registry = journal()?;
                let report = registry
                    .replay(&dnet_netstate::win_route::WindowsUndoExecutor)
                    .map_err(|e| e.to_string())?;
                println!(
                    "replayed: {} restored, {} failed",
                    report.restored,
                    report.failed.len()
                );
                for (_, why) in &report.failed {
                    println!("  could not undo: {why}");
                }
            }
            "status" => {
                let engine = Engine::open().map_err(|e| e.to_string())?;
                println!(
                    "{}",
                    if engine.is_installed().map_err(|e| e.to_string())? {
                        "installed"
                    } else {
                        "not installed"
                    }
                );
            }
            "remove" => {
                let engine = Engine::open().map_err(|e| e.to_string())?;
                engine.remove_all().map_err(|e| e.to_string())?;
                println!("removed");
            }
            other => return Err(format!("unknown command {other}")),
        }
        Ok(())
    }
}
