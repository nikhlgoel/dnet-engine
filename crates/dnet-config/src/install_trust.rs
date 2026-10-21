//! T139 — are the programs the service launches as SYSTEM out of reach of ordinary users?
//!
//! `dnetd` runs as LocalSystem and starts two cores and loads a driver DLL from the folder it was
//! installed in. If an ordinary user can write to that folder, to a program in it, or to anything
//! that lets them swap the folder for another, they can put their own code there and have it run as
//! SYSTEM the next time anyone connects. That is the classic local privilege escalation for a
//! service, and it needs no bug in this code: only an installation that is too open, whether from
//! an installer mistake, a portable copy in a user's folder, or an inherited permission nobody
//! looked at. So the service checks, instead of assuming.
//!
//! The policy is the opposite of `trusted_file`'s. Data files here are closed to everyone but
//! SYSTEM and Administrators. Programs must be *readable and runnable* by ordinary users (the tray
//! and the command line live beside them) but writable by nobody except SYSTEM, Administrators and
//! TrustedInstaller, who own and may change the installation.
//!
//! Three things are checked, each with the rights that matter for it:
//!
//! - the **program** itself: no write, append, delete, change-permissions or take-ownership for an
//!   untrusted trustee, and a trusted owner (an owner can always rewrite the permissions);
//! - the **folder holding the programs**: the same, because creating a file there plants a DLL the
//!   program will load, and deleting one replaces it;
//! - **every folder above it**, up to the drive root: only the rights that let a folder be renamed or
//!   deleted away (delete, delete-child, change-permissions, take-ownership). Creating a new folder
//!   in `C:\` is what any user may do and does not touch an existing one.
//!
//! The reading of permissions is Windows-only; the judgement of them is a function of SDDL text and
//! is tested everywhere. Anything this cannot read or does not understand counts against the
//! installation: the check fails closed.

use std::path::PathBuf;

/// What the object is to the service, which decides which rights are dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A program the service launches or loads.
    Program,
    /// The folder directly holding such programs.
    ProgramFolder,
    /// A folder above that one.
    Ancestor,
}

/// SYSTEM, Administrators, and TrustedInstaller (the owner of the Windows and Program Files trees),
/// in the short form SDDL prefers and the long form it falls back to.
const TRUSTED: [&str; 5] = [
    "SY",
    "BA",
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// File and folder right bits (the same bit means a different thing on a file and on a folder).
mod bit {
    pub const WRITE_DATA: u32 = 0x0000_0002; // file: write; folder: create a file
    pub const APPEND_DATA: u32 = 0x0000_0004; // file: append; folder: create a subfolder
    pub const WRITE_EA: u32 = 0x0000_0010;
    pub const DELETE_CHILD: u32 = 0x0000_0040;
    pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub const DELETE: u32 = 0x0001_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
}

/// The rights that let an untrusted trustee change what runs, for each role.
fn dangerous(role: Role) -> u32 {
    use bit::*;
    let rename_or_retarget = DELETE | DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
    let anything = GENERIC_ALL | GENERIC_WRITE | MAXIMUM_ALLOWED;
    match role {
        Role::Program | Role::ProgramFolder => {
            rename_or_retarget | WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES | anything
        }
        Role::Ancestor => rename_or_retarget | anything,
    }
}

/// A mask from SDDL: hexadecimal (`0x1301bf`) or two-letter names (`FRFX`, `SD`). An unknown name
/// counts as every right, so what is not understood is not trusted.
fn mask_of(text: &str) -> u32 {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).unwrap_or(u32::MAX);
    }
    if text.is_empty() || text.len() % 2 != 0 {
        return u32::MAX;
    }
    let mut mask = 0u32;
    for pair in text.as_bytes().chunks(2) {
        mask |= match pair {
            b"FA" => 0x001f_01ff,
            b"FR" => 0x0012_0089,
            b"FW" => 0x0012_0116,
            b"FX" => 0x0012_00a0,
            b"GA" => bit::GENERIC_ALL,
            b"GR" => 0x8000_0000,
            b"GW" => bit::GENERIC_WRITE,
            b"GX" => 0x2000_0000,
            b"SD" => bit::DELETE,
            b"RC" => 0x0002_0000,
            b"WD" => bit::WRITE_DAC,
            b"WO" => bit::WRITE_OWNER,
            // Directory-service names, which on a file system object are the low bits.
            b"CC" => 0x1,
            b"DC" => 0x2,
            b"LC" => 0x4,
            b"SW" => 0x8,
            b"RP" => 0x10,
            b"WP" => 0x20,
            b"DT" => 0x40,
            b"LO" => 0x80,
            b"CR" => 0x100,
            _ => return u32::MAX,
        };
    }
    mask
}

fn is_trusted(trustee: &str) -> bool {
    TRUSTED.contains(&trustee)
}

/// Judge an object's owner and permissions, given as SDDL (`O:...D:...`).
///
/// `Err` says what is wrong in a sentence an administrator can act on.
pub fn assess_sddl(sddl: &str, role: Role) -> Result<(), String> {
    let rest = sddl
        .strip_prefix("O:")
        .ok_or("the owner could not be read")?;
    // The owner runs up to the next section marker (`G:` or `D:`).
    let end = rest
        .find("G:")
        .into_iter()
        .chain(rest.find("D:"))
        .min()
        .ok_or("the permissions could not be read")?;
    let owner = &rest[..end];
    if !is_trusted(owner) {
        return Err(format!(
            "it is owned by {owner}, who could therefore change its permissions"
        ));
    }
    let dacl = rest
        .find("D:")
        .map(|at| &rest[at + 2..])
        .ok_or("it has no permissions list, which grants everyone full access")?;
    if dacl.starts_with("NO_ACCESS_CONTROL") {
        return Err("it has no access control, which grants everyone full access".to_owned());
    }
    // Flags (P, AI, AR) run up to the first ACE.
    let aces = dacl.split_once('(').map_or("", |(_, aces)| aces);
    let danger = dangerous(role);
    for ace in aces.split(')').map(|a| a.trim_start_matches('(')) {
        if ace.is_empty() {
            continue;
        }
        // type;flags;rights;object guid;inherit guid;trustee [;condition]
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 {
            return Err(format!("a permission entry is not understood: ({ace})"));
        }
        let (kind, flags, rights, trustee) = (fields[0], fields[1], fields[2], fields[5]);
        // Only entries that allow something can open the door; a denial is ignored, which can only
        // make the check stricter than the real permissions.
        if !matches!(kind, "A" | "OA" | "XA" | "ZA") {
            continue;
        }
        // An entry that applies only to children created later does not apply to this object.
        if flags.contains("IO") {
            continue;
        }
        // CREATOR OWNER stands for the owner, which is already required to be trusted.
        if is_trusted(trustee) || trustee == "CO" || trustee == "S-1-3-0" {
            continue;
        }
        if mask_of(rights) & danger != 0 {
            return Err(format!(
                "{} can write to it or change who can ({rights})",
                who(trustee)
            ));
        }
    }
    Ok(())
}

/// A trustee in words, for the message.
fn who(trustee: &str) -> String {
    match trustee {
        "WD" | "S-1-1-0" => "Everyone",
        "BU" | "S-1-5-32-545" => "Users",
        "AU" | "S-1-5-11" => "Authenticated Users",
        "IU" | "S-1-5-4" => "the interactive user",
        "AN" => "anonymous users",
        other => return other.to_owned(),
    }
    .to_owned()
}

/// A problem with an installation: which object, and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {reason}")]
pub struct InstallProblem {
    pub path: String,
    pub reason: String,
}

/// The objects to judge for a set of programs, each with its role, from the program up to the root.
/// Callers pass resolved paths: a link in the way would make the text of the path say one thing and
/// the real location another.
pub fn objects_to_check(programs: &[PathBuf]) -> Vec<(PathBuf, Role)> {
    let mut out: Vec<(PathBuf, Role)> = Vec::new();
    let mut add = |path: PathBuf, role: Role| {
        if !out.iter().any(|(p, _)| *p == path) {
            out.push((path, role));
        }
    };
    for program in programs {
        add(program.clone(), Role::Program);
        let mut dirs = program.ancestors().skip(1);
        if let Some(folder) = dirs.next() {
            add(folder.to_path_buf(), Role::ProgramFolder);
        }
        for above in dirs {
            add(above.to_path_buf(), Role::Ancestor);
        }
    }
    out
}

#[cfg(windows)]
pub use windows_check::verify_programs;

#[cfg(windows)]
mod windows_check {
    use std::path::Path;

    use super::*;
    use crate::write::win;

    /// Check that each program, the folder holding it, and every folder above are out of reach of
    /// ordinary users. Paths are resolved first (links and junctions followed), because the rights
    /// that matter are those of the place the program really is.
    pub fn verify_programs(programs: &[PathBuf]) -> Result<(), InstallProblem> {
        let mut resolved = Vec::with_capacity(programs.len());
        for program in programs {
            let real = std::fs::canonicalize(program).map_err(|e| InstallProblem {
                path: program.display().to_string(),
                reason: format!("it cannot be found ({})", e.kind()),
            })?;
            resolved.push(strip_verbatim(&real));
        }
        for (path, role) in objects_to_check(&resolved) {
            let sddl = win::read_owner_and_dacl_sddl(&path).map_err(|e| InstallProblem {
                path: path.display().to_string(),
                reason: format!("its permissions could not be read ({})", e.kind()),
            })?;
            assess_sddl(&sddl, role).map_err(|reason| InstallProblem {
                path: path.display().to_string(),
                reason,
            })?;
        }
        Ok(())
    }

    /// `\\?\C:\x` is how `canonicalize` spells `C:\x`; the permission calls take either, but the
    /// walk up the path must end at the drive, so the prefix is dropped.
    fn strip_verbatim(path: &Path) -> PathBuf {
        let text = path.as_os_str().to_string_lossy();
        match text.strip_prefix(r"\\?\") {
            Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
            _ => path.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const TI: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// `C:\Program Files\<product>` as Windows creates it.
    fn program_files() -> String {
        format!(
            "O:{TI}G:{TI}D:PAI(A;;FA;;;{TI})(A;CIIO;GA;;;{TI})(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)\
             (A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)\
             (A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)"
        )
    }

    /// The root of the system drive: ordinary users may create folders there.
    fn drive_root() -> &'static str {
        "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;SDGXGWGR;;;IU)\
         (A;;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;CIIO;DC;;;BU)(A;OICIIO;GA;;;CO)"
    }

    #[test]
    fn a_normal_program_files_folder_is_trusted_in_every_role() {
        for role in [Role::Program, Role::ProgramFolder, Role::Ancestor] {
            assert_eq!(assess_sddl(&program_files(), role), Ok(()), "{role:?}");
        }
    }

    #[test]
    fn users_creating_folders_in_the_drive_root_is_harmless_to_a_folder_below_it() {
        assert_eq!(assess_sddl(drive_root(), Role::Ancestor), Ok(()));
    }

    #[test]
    fn the_same_permission_on_the_folder_holding_the_programs_is_not() {
        // "Users: add a subfolder" on the folder itself lets a user plant a DLL beside the program.
        let sddl = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;LC;;;BU)";
        let err = assess_sddl(sddl, Role::ProgramFolder).unwrap_err();
        assert!(err.contains("Users"), "{err}");
    }

    #[test]
    fn a_folder_owned_by_an_ordinary_user_is_refused_even_with_clean_entries() {
        let sddl = "O:S-1-5-21-111-222-333-1001G:S-1-5-21-111-222-333-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        let err = assess_sddl(sddl, Role::Ancestor).unwrap_err();
        assert!(
            err.contains("owned by"),
            "an owner can rewrite the permissions: {err}"
        );
    }

    #[test]
    fn modify_rights_for_users_make_a_program_untrusted() {
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)";
        for role in [Role::Program, Role::ProgramFolder, Role::Ancestor] {
            assert!(assess_sddl(sddl, role).is_err(), "{role:?}");
        }
    }

    #[test]
    fn full_control_for_a_named_user_is_caught() {
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-111-222-333-1001)";
        assert!(assess_sddl(sddl, Role::Program).is_err());
    }

    #[test]
    fn everyone_with_write_is_caught_and_named() {
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FW;;;WD)";
        let err = assess_sddl(sddl, Role::Program).unwrap_err();
        assert!(err.contains("Everyone"), "{err}");
    }

    #[test]
    fn read_and_execute_for_users_is_what_a_program_should_have() {
        let sddl =
            "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;FR;;;WD)(A;;FX;;;AU)";
        assert_eq!(assess_sddl(sddl, Role::Program), Ok(()));
    }

    #[test]
    fn deleting_a_folder_away_matters_above_the_program_though_creating_in_it_does_not() {
        let delete_child = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;DT;;;BU)";
        assert!(assess_sddl(delete_child, Role::Ancestor).is_err());
        let change_perms = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;WD;;;AU)";
        assert!(assess_sddl(change_perms, Role::Ancestor).is_err());
        let take_ownership = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;WO;;;AU)";
        assert!(assess_sddl(take_ownership, Role::Ancestor).is_err());
    }

    #[test]
    fn an_entry_that_only_applies_to_things_created_later_does_not_count() {
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;BU)";
        assert_eq!(assess_sddl(sddl, Role::Program), Ok(()));
    }

    #[test]
    fn a_denial_does_not_make_up_for_an_allowance() {
        // Strictness by design: the allowance is what is reported, whatever denies follow it.
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;0x1301bf;;;BU)(D;;FW;;;BU)";
        assert!(assess_sddl(sddl, Role::Program).is_err());
    }

    #[test]
    fn no_access_control_at_all_is_everyone_full_control() {
        assert!(assess_sddl("O:BAG:BAD:NO_ACCESS_CONTROL", Role::Program).is_err());
        assert!(
            assess_sddl("O:BAG:BA", Role::Program).is_err(),
            "no list at all"
        );
    }

    #[test]
    fn what_cannot_be_read_or_understood_is_not_trusted() {
        assert!(assess_sddl("", Role::Program).is_err());
        assert!(
            assess_sddl("G:BAD:PAI(A;;FA;;;SY)", Role::Program).is_err(),
            "no owner"
        );
        assert!(
            assess_sddl("O:BAG:BAD:PAI(A;;FA;;SY)", Role::Program).is_err(),
            "short entry"
        );
        // An unknown right name counts as every right.
        assert!(assess_sddl("O:BAG:BAD:PAI(A;;QQ;;;BU)", Role::Program).is_err());
        assert!(assess_sddl("O:BAG:BAD:PAI(A;;0xZZ;;;BU)", Role::Program).is_err());
    }

    #[test]
    fn rights_are_read_whether_named_or_hexadecimal() {
        assert_eq!(mask_of("0x1200a9") & dangerous(Role::Program), 0);
        assert_ne!(mask_of("0x1301bf") & dangerous(Role::Program), 0);
        assert_ne!(mask_of("FW") & dangerous(Role::Program), 0);
        assert_eq!(mask_of("FRFX") & dangerous(Role::Program), 0);
        assert_ne!(mask_of("GA") & dangerous(Role::Ancestor), 0);
        assert_eq!(mask_of("LC") & dangerous(Role::Ancestor), 0);
        assert_ne!(mask_of("LC") & dangerous(Role::ProgramFolder), 0);
    }

    // ------------------------------------------------------------------ which objects are judged

    #[test]
    fn the_program_its_folder_and_every_folder_above_are_judged_once_each() {
        let programs = [
            PathBuf::from("/opt/dnet/dnetd.exe"),
            PathBuf::from("/opt/dnet/core.exe"),
        ];
        let got = objects_to_check(&programs);
        let roles = |role| got.iter().filter(|(_, r)| *r == role).count();
        assert_eq!(roles(Role::Program), 2);
        assert_eq!(roles(Role::ProgramFolder), 1, "the shared folder once");
        assert!(got
            .iter()
            .any(|(p, r)| p == Path::new("/opt") && *r == Role::Ancestor));
        assert!(got
            .iter()
            .any(|(p, r)| p == Path::new("/") && *r == Role::Ancestor));
        assert_eq!(got.len(), 5);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::path::PathBuf;

    use super::*;

    /// A folder under this user's temporary directory is owned by this user: not a place to run
    /// SYSTEM's programs from, and the check must say so.
    #[test]
    fn a_program_in_a_users_own_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("core.exe");
        std::fs::write(&exe, b"x").unwrap();

        let problem = verify_programs(&[exe]).unwrap_err();

        assert!(
            problem.reason.contains("owned by") || problem.reason.contains("can write"),
            "{problem}"
        );
    }

    #[test]
    fn a_program_that_is_not_there_is_a_problem_not_a_pass() {
        let problem = verify_programs(&[PathBuf::from(r"C:\no\such\program.exe")]).unwrap_err();
        assert!(problem.reason.contains("cannot be found"), "{problem}");
    }

    /// A real, protected location: the system's own `cmd.exe` and every folder above it.
    #[test]
    fn the_systems_own_program_folder_is_trusted() {
        let windows = std::env::var_os("SystemRoot").expect("Windows sets SystemRoot");
        let cmd = PathBuf::from(windows).join("System32").join("cmd.exe");
        verify_programs(&[cmd]).expect("System32 is protected from ordinary users");
    }
}
