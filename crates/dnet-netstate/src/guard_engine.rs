//! T161 step 3 — the guard in the Windows Filtering Platform (ADR-0006 §5a; `docs/research/2026-10-31-solutions.md` §4).
//!
//! This is the only place that calls the firewall engine. It takes rules already translated by [`crate::guard_wfp`]
//! (which took them from a `dnet_core::guard::Guard`, which refuses a list that leaks) and does exactly four things:
//!
//! - [`Engine::apply`]: replace the guard with this list, **all or nothing**, in one transaction. The provider, the
//!   sublayer and every filter are *persistent*, and the provider names the `DNetEngine` service: a persistent
//!   object of a provider that names a service is applied at start only if that service is auto-start, so a disabled
//!   or uninstalled service lifts the block at the next start (the lockout safety), and a crashed service does not
//!   lift it (the kill switch).
//! - [`Engine::read_back`]: what the firewall holds under our provider, in the translation's terms, so the model's
//!   `verify` can compare it with the plan in both directions.
//! - [`Engine::remove_all`]: every filter, the sublayer and the provider, in one transaction. Removing what is not
//!   there is not an error.
//! - [`Engine::is_installed`].
//!
//! It touches only objects that belong to [`PROVIDER_KEY`] and [`SUBLAYER_KEY`]: it deletes by enumerating its own
//! provider's filters, never by a key it was handed. A lock timeout on the engine is a published failure of a
//! comparable guard, so a transaction is tried again a few times before it is reported.

use std::ffi::c_void;
use std::ptr;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_MATCH_TYPE,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

use dnet_core::guard::Action;

use crate::error::NetstateError;
use crate::undo::{Mutation, UndoRecord, UndoRegistry};

use crate::guard_wfp::{
    Guid, Layer, Match, WfpFilter, PROVIDER_KEY, PROVIDER_NAME, SERVICE_NAME, SUBLAYER_KEY,
    SUBLAYER_NAME,
};

/// The engine's "already exists" and "not found" answers, and the two that mean "try again".
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_IN_USE: u32 = 0x8032_000A;
const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
const FWP_E_TXN_IN_PROGRESS: u32 = 0x8032_000E;
const FWP_E_TIMEOUT: u32 = 0x8032_0012;

/// A sublayer weight high enough to be looked at before the system firewall's own, low enough to leave room.
const SUBLAYER_WEIGHT: u16 = 0xFFF0;

/// How many times a transaction that timed out is tried, and how long to wait between.
const ATTEMPTS: u32 = 4;
const RETRY_WAIT: std::time::Duration = std::time::Duration::from_millis(400);

/// What the firewall engine said, and to which call. The code is the engine's own, in hex: it is what the
/// documentation and a search for it use.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("the firewall engine refused {call} (0x{code:08X})")]
    Call { call: &'static str, code: u32 },
    #[error(
        "the firewall holds a rule under the guard's provider that is not one of its own: {0}"
    )]
    Foreign(String),
    #[error("{0}")]
    Invalid(String),
}

impl EngineError {
    fn code(&self) -> Option<u32> {
        match self {
            EngineError::Call { code, .. } => Some(*code),
            _ => None,
        }
    }
}

fn check(call: &'static str, code: u32) -> Result<(), EngineError> {
    if code == 0 {
        Ok(())
    } else {
        Err(EngineError::Call { call, code })
    }
}

/// Like [`check`], but an object that is already there is fine: when something that is not ours still sits in our
/// sublayer, the removal leaves the (empty) sublayer and provider behind, and the next guard must go in under them
/// rather than fail for ever because they exist (review 2026-11-10). The keys are fixed and ours; the filters, which
/// are what block, are always made fresh.
fn exists_is_fine(call: &'static str, code: u32) -> Result<(), EngineError> {
    if code == FWP_E_ALREADY_EXISTS {
        Ok(())
    } else {
        check(call, code)
    }
}

fn to_guid(g: Guid) -> GUID {
    GUID {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}

fn from_guid(g: &GUID) -> Guid {
    Guid {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}

/// A NUL-terminated UTF-16 copy of `text`, which the engine reads for as long as a call lasts.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A security identifier in text: `S-1-` and then digits and dashes, nothing else. It goes into a descriptor string,
/// so anything that is not exactly that is refused rather than escaped.
fn is_sid_text(text: &str) -> bool {
    text.len() >= 6
        && text.len() <= 184
        && text.starts_with("S-1-")
        && text[4..].chars().all(|c| c.is_ascii_digit() || c == '-')
        && !text.ends_with('-')
        && !text.contains("--")
}

/// A filter of ours as the engine listed it: its id, and what reading it came to.
type Listed = (u64, Result<WfpFilter, EngineError>);

/// The engine, open. Closed when dropped.
pub struct Engine(HANDLE);

impl Engine {
    /// Open the engine on this computer.
    pub fn open() -> Result<Self, EngineError> {
        let mut handle = HANDLE::default();
        // SAFETY: a null server name is this computer; `handle` is a valid place for the result.
        let code = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                None,
                None,
                &mut handle,
            )
        };
        check("FwpmEngineOpen0", code)?;
        Ok(Self(handle))
    }

    /// Run `work` in one transaction: committed if it returns `Ok`, abandoned if not. A transaction the engine
    /// could not start or finish in time is tried again.
    fn transaction<T>(
        &self,
        mut work: impl FnMut(&Self) -> Result<T, EngineError>,
    ) -> Result<T, EngineError> {
        let mut last = None;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(RETRY_WAIT);
            }
            // SAFETY: the handle is open for as long as `self` lives.
            let begun = check("FwpmTransactionBegin0", unsafe {
                FwpmTransactionBegin0(self.0, 0)
            });
            if let Err(e) = begun {
                if matches!(e.code(), Some(FWP_E_TIMEOUT | FWP_E_TXN_IN_PROGRESS)) {
                    last = Some(e);
                    continue;
                }
                return Err(e);
            }
            match work(self) {
                Ok(value) => {
                    // SAFETY: a transaction is open on this handle.
                    match check("FwpmTransactionCommit0", unsafe {
                        FwpmTransactionCommit0(self.0)
                    }) {
                        Ok(()) => return Ok(value),
                        Err(e) => {
                            last = Some(e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // SAFETY: a transaction is open on this handle; abandoning it undoes everything in it.
                    unsafe { FwpmTransactionAbort0(self.0) };
                    return Err(e);
                }
            }
        }
        Err(last.unwrap_or(EngineError::Call {
            call: "transaction",
            code: FWP_E_TIMEOUT,
        }))
    }

    /// Whether any filter of the guard is in the firewall. It is the filters that block, not the provider or the
    /// sublayer they hang from: when something that is not ours sits in our sublayer, a removal leaves the empty
    /// sublayer and provider behind (they are in use), and that is not a guard (review 2026-11-10).
    pub fn is_installed(&self) -> Result<bool, EngineError> {
        let mut any = false;
        self.each_ours(|_| any = true)?;
        Ok(any)
    }

    /// Replace the guard with `filters`, all or nothing.
    pub fn apply(&self, filters: &[WfpFilter]) -> Result<(), EngineError> {
        self.transaction(|engine| {
            engine.remove_ours()?;
            engine.add_provider()?;
            engine.add_sublayer()?;
            for filter in filters {
                engine.add_filter(filter).map_err(|e| {
                    // The rule's name only: its conditions hold program paths, an account and a port.
                    EngineError::Invalid(format!("{e}, for the rule `{}`", filter.name))
                })?;
            }
            Ok(())
        })
    }

    /// Take the guard out: every filter, the sublayer and the provider. Nothing there is not an error.
    pub fn remove_all(&self) -> Result<(), EngineError> {
        self.transaction(|engine| engine.remove_ours())
    }

    /// Delete our filters (found by enumerating our provider), then the sublayer and the provider.
    fn remove_ours(&self) -> Result<(), EngineError> {
        for id in self.our_filter_ids()? {
            // SAFETY: an id the engine just listed, in an open transaction.
            let code = unsafe { FwpmFilterDeleteById0(self.0, id) };
            if code != 0 && code != FWP_E_NOT_FOUND {
                return Err(EngineError::Call {
                    call: "FwpmFilterDeleteById0",
                    code,
                });
            }
        }
        // `in use` means something that is not ours still sits in our sublayer or under our provider. That must not
        // stop our own filters from going (they are deleted above, in this same transaction): a guard nobody can take
        // out is worse than a sublayer left behind (review 2026-11-10, finding 2).
        let sublayer = to_guid(SUBLAYER_KEY);
        // SAFETY: a key that is ours, in an open transaction.
        let code = unsafe { FwpmSubLayerDeleteByKey0(self.0, &sublayer) };
        if code != 0
            && !matches!(
                code,
                FWP_E_SUBLAYER_NOT_FOUND | FWP_E_NOT_FOUND | FWP_E_IN_USE
            )
        {
            return Err(EngineError::Call {
                call: "FwpmSubLayerDeleteByKey0",
                code,
            });
        }
        let provider = to_guid(PROVIDER_KEY);
        // SAFETY: as above.
        let code = unsafe { FwpmProviderDeleteByKey0(self.0, &provider) };
        if code != 0
            && !matches!(
                code,
                FWP_E_PROVIDER_NOT_FOUND | FWP_E_NOT_FOUND | FWP_E_IN_USE
            )
        {
            return Err(EngineError::Call {
                call: "FwpmProviderDeleteByKey0",
                code,
            });
        }
        Ok(())
    }

    fn add_provider(&self) -> Result<(), EngineError> {
        let mut name = wide(PROVIDER_NAME);
        let mut service = wide(SERVICE_NAME);
        let provider = FWPM_PROVIDER0 {
            providerKey: to_guid(PROVIDER_KEY),
            displayData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    description: PWSTR::null(),
                },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: FWP_BYTE_BLOB::default(),
            serviceName: PWSTR(service.as_mut_ptr()),
        };
        // SAFETY: `provider` and the strings it points at live across the call; no security descriptor is given.
        exists_is_fine("FwpmProviderAdd0", unsafe {
            FwpmProviderAdd0(self.0, &provider, PSECURITY_DESCRIPTOR::default())
        })
    }

    fn add_sublayer(&self) -> Result<(), EngineError> {
        let mut name = wide(SUBLAYER_NAME);
        let mut provider = to_guid(PROVIDER_KEY);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: to_guid(SUBLAYER_KEY),
            displayData:
                windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: PWSTR(name.as_mut_ptr()),
                    description: PWSTR::null(),
                },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider,
            providerData: FWP_BYTE_BLOB::default(),
            weight: SUBLAYER_WEIGHT,
        };
        // SAFETY: as for the provider; `provider` outlives the call.
        exists_is_fine("FwpmSubLayerAdd0", unsafe {
            FwpmSubLayerAdd0(self.0, &sublayer, PSECURITY_DESCRIPTOR::default())
        })
    }

    fn add_filter(&self, filter: &WfpFilter) -> Result<(), EngineError> {
        let mut built = Conditions::default();
        for m in &filter.matches {
            built.push(m)?;
        }
        let mut name = wide(&filter.name);
        let mut provider = to_guid(PROVIDER_KEY);
        let mut raw = FWPM_FILTER0::default();
        raw.displayData.name = PWSTR(name.as_mut_ptr());
        raw.flags = FWPM_FILTER_FLAG_PERSISTENT;
        raw.providerKey = &mut provider;
        raw.layerKey = layer_key(filter.layer);
        raw.subLayerKey = to_guid(SUBLAYER_KEY);
        raw.weight = FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 {
                uint8: filter.weight,
            },
        };
        raw.numFilterConditions = u32::try_from(built.list.len())
            .map_err(|_| EngineError::Invalid("too many conditions".into()))?;
        raw.filterCondition = if built.list.is_empty() {
            ptr::null_mut()
        } else {
            built.list.as_mut_ptr()
        };
        raw.action.r#type = match filter.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let mut id = 0u64;
        // SAFETY: `raw` and everything it points at (the name, the provider key, the conditions and their values)
        // live until after the call returns; the engine copies them.
        let code =
            unsafe { FwpmFilterAdd0(self.0, &raw, PSECURITY_DESCRIPTOR::default(), Some(&mut id)) };
        drop(built);
        check("FwpmFilterAdd0", code)
    }

    /// The filters under our provider, as engine ids with their rule, in the engine's order.
    ///
    /// Every filter the engine holds is listed and only those whose provider is ours are read: a template naming a
    /// provider alone is refused by the engine (it wants a layer too), and one layer at a time would miss a filter
    /// somebody put at a layer the guard does not use, which is exactly what the read-back must see. Another
    /// provider's filters are never decoded and never touched.
    fn enumerate_raw(&self) -> Result<Vec<Listed>, EngineError> {
        let mut found = Vec::new();
        self.each_ours(|filter| found.push((filter.filterId, decode_filter(filter))))?;
        Ok(found)
    }

    /// The engine ids of our filters, and nothing else: no field of a filter is read except the id and the provider
    /// key. Removal uses this, so the way out never depends on a filter being well formed (T161, review 2026-11-10).
    fn our_filter_ids(&self) -> Result<Vec<u64>, EngineError> {
        let mut ids = Vec::new();
        self.each_ours(|filter| ids.push(filter.filterId))?;
        Ok(ids)
    }

    /// Visit each filter whose provider is ours, once, while the engine's block is still alive.
    fn each_ours(&self, mut visit: impl FnMut(&FWPM_FILTER0)) -> Result<(), EngineError> {
        let ours = to_guid(PROVIDER_KEY);
        self.each_filter(|filter| {
            // SAFETY: a non-null provider key points at a GUID the engine owns for as long as the block lives.
            let is_ours = !filter.providerKey.is_null() && unsafe { *filter.providerKey } == ours;
            if is_ours {
                visit(filter);
            }
        })
    }

    /// How many filters that are **not ours** sit in the guard's sublayer. Our block has the lowest weight there is,
    /// so a permit of another provider in the same sublayer ties with it and can win: only an administrator can put
    /// one there, but a guard that reads back as verified while one is present would overstate its protection
    /// (found in the lab, review 2026-11-10). Nothing of a foreign filter is read except where it sits.
    pub fn foreign_in_our_sublayer(&self) -> Result<usize, EngineError> {
        let provider = to_guid(PROVIDER_KEY);
        let sublayer = to_guid(SUBLAYER_KEY);
        let mut found = 0usize;
        self.each_filter(|filter| {
            // SAFETY: a non-null provider key points at a GUID the engine owns for as long as the block lives.
            let is_ours =
                !filter.providerKey.is_null() && unsafe { *filter.providerKey } == provider;
            if !is_ours && filter.subLayerKey == sublayer {
                found += 1;
            }
        })?;
        Ok(found)
    }

    /// Visit every filter the engine holds, once, while the engine's block is still alive.
    fn each_filter(&self, mut visit: impl FnMut(&FWPM_FILTER0)) -> Result<(), EngineError> {
        let mut handle = HANDLE::default();
        // SAFETY: no template lists everything; `handle` is a valid place for the result.
        check("FwpmFilterCreateEnumHandle0", unsafe {
            FwpmFilterCreateEnumHandle0(self.0, None, &mut handle)
        })?;
        let mut outcome = Ok(());
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
            let mut count = 0u32;
            // SAFETY: the enum handle is open; `entries` and `count` are valid for the call.
            let code = unsafe { FwpmFilterEnum0(self.0, handle, 64, &mut entries, &mut count) };
            if code != 0 {
                outcome = Err(EngineError::Call {
                    call: "FwpmFilterEnum0",
                    code,
                });
                break;
            }
            if !entries.is_null() {
                for i in 0..count as usize {
                    // SAFETY: the engine returned `count` valid pointers; each is read before the block is freed.
                    visit(unsafe { &**entries.add(i) });
                }
                // SAFETY: the block the engine allocated, freed once (also when it held no entries).
                unsafe {
                    FwpmFreeMemory0(&mut entries as *mut *mut *mut FWPM_FILTER0 as *mut *mut c_void)
                };
            }
            if count == 0 {
                break;
            }
        }
        // SAFETY: the enum handle was opened above.
        unsafe { FwpmFilterDestroyEnumHandle0(self.0, handle) };
        outcome
    }

    /// What the firewall holds under our provider, in the translation's terms. A program in a rule is shown as the
    /// path in `known_programs` whose engine form it is; any other program is shown as an unknown one, which the
    /// model's check then reports as a permit nobody asked for.
    pub fn read_back(&self, known_programs: &[String]) -> Result<Vec<WfpFilter>, EngineError> {
        let mut forms = Vec::new();
        for path in known_programs {
            forms.push((path.clone(), app_id_bytes(path)?));
        }
        let mut out = Vec::new();
        for (_, decoded) in self.enumerate_raw()? {
            let mut filter = decoded?;
            for m in &mut filter.matches {
                if let Match::AppId(blob_text) = m {
                    if let Some(bytes) = decode_hex(blob_text) {
                        *blob_text = forms.iter().find(|(_, form)| *form == bytes).map_or_else(
                            || "<a program the guard did not ask for>".to_owned(),
                            |(path, _)| path.clone(),
                        );
                    }
                }
            }
            out.push(filter);
        }
        Ok(out)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `open` and is closed once.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::AleAuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::AleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// Whether the engine's form of a program (its NT path, as UTF-16) lies on a local volume: `\device\harddiskvolumeN\`.
/// A network share (`\device\mup\...`), a `\??\` alias and anything else is not one. The guard's permit follows a file
/// by this form, so it must not be a file somebody else's machine controls (review 2026-11-10, finding 7).
fn is_local_volume_app_id(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() & 1 == 1 {
        return false;
    }
    let units: Vec<u16> = (0..bytes.len() / 2)
        .map(|i| u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
        .take_while(|&u| u != 0)
        .collect();
    let path = String::from_utf16_lossy(&units).to_ascii_lowercase();
    let Some(rest) = path.strip_prefix(r"\device\harddiskvolume") else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && rest[digits..].starts_with('\\')
}

/// The engine's own form of a program's full path (an NT path, lower-cased), as a blob.
fn app_id_bytes(path: &str) -> Result<Vec<u8>, EngineError> {
    let path_w = wide(path);
    let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
    // SAFETY: a NUL-terminated path and a valid place for the pointer the engine allocates.
    check("FwpmGetAppIdFromFileName0", unsafe {
        FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut blob)
    })?;
    // SAFETY: the engine returned a blob of `size` bytes at `data`; it is copied, then freed once.
    let bytes = unsafe { std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec() };
    unsafe { FwpmFreeMemory0(&mut blob as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
    if !is_local_volume_app_id(&bytes) {
        return Err(EngineError::Invalid(format!(
            "{path} does not resolve to a file on a local volume, so no permit will follow it"
        )));
    }
    Ok(bytes)
}

/// The security identifier a descriptor's trustee stands for: written out in full, or one of the two-letter names the
/// system uses for the well-known ones. A name this does not know is not guessed at (`None`): the read-back then says
/// the rule is not one of the guard's own, which is the safe answer.
fn sid_of_trustee(trustee: &str) -> Option<String> {
    if is_sid_text(trustee) {
        return Some(trustee.to_owned());
    }
    let sid = match trustee {
        "WD" => "S-1-1-0",
        "CO" => "S-1-3-0",
        "CG" => "S-1-3-1",
        "NU" => "S-1-5-2",
        "IU" => "S-1-5-4",
        "SU" => "S-1-5-6",
        "AN" => "S-1-5-7",
        "AU" => "S-1-5-11",
        "SY" => "S-1-5-18",
        "LS" => "S-1-5-19",
        "NS" => "S-1-5-20",
        "BA" => "S-1-5-32-544",
        "BU" => "S-1-5-32-545",
        "BG" => "S-1-5-32-546",
        _ => return None,
    };
    Some(sid.to_owned())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() & 1 == 1 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The conditions of one filter, with the memory their values point at, kept alive until the filter is added.
#[derive(Default)]
#[allow(clippy::vec_box)] // the boxes keep each value where the condition's raw pointer says it is, as the Vec grows
struct Conditions {
    list: Vec<FWPM_FILTER_CONDITION0>,
    luids: Vec<Box<u64>>,
    blobs: Vec<Box<FWP_BYTE_BLOB>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    /// Engine-allocated program ids, freed on drop.
    app_ids: Vec<*mut FWP_BYTE_BLOB>,
    /// System-allocated security descriptors, freed on drop.
    descriptors: Vec<PSECURITY_DESCRIPTOR>,
}

impl Conditions {
    fn push(&mut self, m: &Match) -> Result<(), EngineError> {
        let equal = |key: GUID, value: FWP_CONDITION_VALUE0| FWPM_FILTER_CONDITION0 {
            fieldKey: key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: value,
        };
        let number = |r#type, value: FWP_CONDITION_VALUE0_0| FWP_CONDITION_VALUE0 {
            r#type,
            Anonymous: value,
        };
        let condition = match m {
            Match::LocalInterface(luid) => {
                self.luids.push(Box::new(*luid));
                let place = self
                    .luids
                    .last_mut()
                    .map(|b| &mut **b as *mut u64)
                    .unwrap_or(ptr::null_mut());
                equal(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    number(FWP_UINT64, FWP_CONDITION_VALUE0_0 { uint64: place }),
                )
            }
            Match::AppId(path) => {
                let path_w = wide(path);
                let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
                // SAFETY: a NUL-terminated path and a valid place for the pointer the engine allocates.
                check("FwpmGetAppIdFromFileName0", unsafe {
                    FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut blob)
                })?;
                self.app_ids.push(blob);
                equal(
                    FWPM_CONDITION_ALE_APP_ID,
                    number(
                        FWP_BYTE_BLOB_TYPE,
                        FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                    ),
                )
            }
            Match::UserId(sid) => {
                if !is_sid_text(sid) {
                    return Err(EngineError::Invalid(
                        "an account that is not a security identifier".into(),
                    ));
                }
                let sddl = wide(&format!("O:LSD:(A;;CC;;;{sid})"));
                let mut descriptor = PSECURITY_DESCRIPTOR::default();
                // SAFETY: a NUL-terminated descriptor string and a valid place for the descriptor it allocates.
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        PCWSTR(sddl.as_ptr()),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        None,
                    )
                }
                .map_err(|e| EngineError::Call {
                    call: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                    code: e.code().0 as u32,
                })?;
                self.descriptors.push(descriptor);
                // SAFETY: the descriptor was just made and is valid.
                let size = unsafe { GetSecurityDescriptorLength(descriptor) };
                self.blobs.push(Box::new(FWP_BYTE_BLOB {
                    size,
                    data: descriptor.0 as *mut u8,
                }));
                let blob = self
                    .blobs
                    .last_mut()
                    .map(|b| &mut **b as *mut FWP_BYTE_BLOB)
                    .unwrap_or(ptr::null_mut());
                equal(
                    FWPM_CONDITION_ALE_USER_ID,
                    number(
                        FWP_SECURITY_DESCRIPTOR_TYPE,
                        FWP_CONDITION_VALUE0_0 { sd: blob },
                    ),
                )
            }
            Match::Loopback => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_ALL_SET,
                conditionValue: number(
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                ),
            },
            Match::Protocol(p) => equal(
                FWPM_CONDITION_IP_PROTOCOL,
                number(FWP_UINT8, FWP_CONDITION_VALUE0_0 { uint8: *p }),
            ),
            Match::LocalPort(p) => equal(
                FWPM_CONDITION_IP_LOCAL_PORT,
                number(FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *p }),
            ),
            Match::RemotePort(p) => equal(
                FWPM_CONDITION_IP_REMOTE_PORT,
                number(FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: *p }),
            ),
            // The ICMP type is carried in the local-port field of an ICMP packet (the engine's own convention).
            Match::IcmpType(t) => equal(
                FWPM_CONDITION_IP_LOCAL_PORT,
                number(
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 {
                        uint16: u16::from(*t),
                    },
                ),
            ),
            Match::RemoteV4 { addr, prefix } => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(*prefix))
                };
                self.v4.push(Box::new(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(*addr),
                    mask,
                }));
                let place = self
                    .v4
                    .last_mut()
                    .map(|b| &mut **b as *mut FWP_V4_ADDR_AND_MASK)
                    .unwrap_or(ptr::null_mut());
                equal(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    number(
                        FWP_V4_ADDR_MASK,
                        FWP_CONDITION_VALUE0_0 { v4AddrMask: place },
                    ),
                )
            }
            Match::RemoteV6 { addr, prefix } => {
                self.v6.push(Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: *addr,
                    prefixLength: *prefix,
                }));
                let place = self
                    .v6
                    .last_mut()
                    .map(|b| &mut **b as *mut FWP_V6_ADDR_AND_MASK)
                    .unwrap_or(ptr::null_mut());
                equal(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    number(
                        FWP_V6_ADDR_MASK,
                        FWP_CONDITION_VALUE0_0 { v6AddrMask: place },
                    ),
                )
            }
        };
        self.list.push(condition);
        Ok(())
    }
}

impl Drop for Conditions {
    fn drop(&mut self) {
        for blob in self.app_ids.drain(..) {
            let mut blob = blob;
            // SAFETY: allocated by the engine in `push`, freed once.
            unsafe { FwpmFreeMemory0(&mut blob as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
        }
        for descriptor in self.descriptors.drain(..) {
            // SAFETY: allocated by the system in `push`, freed once.
            unsafe { LocalFree(HLOCAL(descriptor.0)) };
        }
    }
}

/// One engine filter in the translation's terms. A program is returned as hex of its engine form, which
/// [`Engine::read_back`] then names from the programs it was told about.
fn decode_filter(filter: &FWPM_FILTER0) -> Result<WfpFilter, EngineError> {
    let foreign = |what: &str| EngineError::Foreign(what.to_owned());
    let name = if filter.displayData.name.is_null() {
        String::new()
    } else {
        // SAFETY: the engine gave a NUL-terminated string that lives as long as the block it came in.
        unsafe { filter.displayData.name.to_string() }.unwrap_or_default()
    };
    let layer = if filter.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4 {
        Layer::AleAuthConnectV4
    } else if filter.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        Layer::AleAuthConnectV6
    } else if filter.layerKey == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 {
        Layer::AleAuthRecvAcceptV4
    } else if filter.layerKey == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 {
        Layer::AleAuthRecvAcceptV6
    } else {
        return Err(foreign(&format!(
            "{name}: it is at a layer the guard does not use"
        )));
    };
    let action = if filter.action.r#type == FWP_ACTION_PERMIT {
        Action::Permit
    } else if filter.action.r#type == FWP_ACTION_BLOCK {
        Action::Block
    } else {
        return Err(foreign(&format!(
            "{name}: it is neither a permit nor a block"
        )));
    };
    if filter.weight.r#type != FWP_UINT8 {
        return Err(foreign(&format!(
            "{name}: its weight is not one the guard sets"
        )));
    }
    // A guard that lost its persistent flag, or sits in another sublayer, would verify clean and not survive a restart
    // or be ordered as planned (review 2026-11-10, finding 8).
    if filter.flags.0 & FWPM_FILTER_FLAG_PERSISTENT.0 == 0 {
        return Err(foreign(&format!("{name}: it is not persistent")));
    }
    if filter.subLayerKey != to_guid(SUBLAYER_KEY) {
        return Err(foreign(&format!(
            "{name}: it is not in the guard's sublayer"
        )));
    }
    // SAFETY: the type says the byte is the member that was set.
    let weight = unsafe { filter.weight.Anonymous.uint8 };
    let mut matches = Vec::with_capacity(filter.numFilterConditions as usize);
    for i in 0..filter.numFilterConditions as usize {
        // SAFETY: the engine returned `numFilterConditions` conditions at `filterCondition`.
        let condition = unsafe { &*filter.filterCondition.add(i) };
        matches.push(decode_condition(condition, &name)?);
    }
    // The ICMP type travels in the local-port field: with protocol 58 present, that field is the type, and it
    // is put straight after the protocol, the way the translation writes it.
    if matches.contains(&Match::Protocol(58)) {
        let at = matches
            .iter()
            .position(|m| *m == Match::Protocol(58))
            .unwrap_or(0);
        if let Some(port) = matches
            .iter()
            .position(|m| matches!(m, Match::LocalPort(_)))
        {
            if let Match::LocalPort(value) = matches.remove(port) {
                let at = if port < at { at - 1 } else { at };
                matches.insert(
                    at + 1,
                    Match::IcmpType(
                        u8::try_from(value)
                            .map_err(|_| foreign(&format!("{name}: an ICMP type above 255")))?,
                    ),
                );
            }
        }
    }
    Ok(WfpFilter {
        name,
        layer,
        action,
        weight,
        matches,
    })
}

fn decode_condition(c: &FWPM_FILTER_CONDITION0, name: &str) -> Result<Match, EngineError> {
    let foreign = |what: &str| EngineError::Foreign(format!("{name}: {what}"));
    let value = &c.conditionValue;
    let key = c.fieldKey;
    // Every condition the guard writes is an equality, except the loopback flag (all bits set): any other way of
    // matching would be a different rule that reads back the same.
    let expected = if key == FWPM_CONDITION_FLAGS {
        FWP_MATCH_FLAGS_ALL_SET
    } else {
        FWP_MATCH_EQUAL
    };
    if c.matchType != expected {
        return Err(foreign(
            "a condition that does not match the way the guard writes it",
        ));
    }
    // SAFETY (for every read of `value.Anonymous` below): each is guarded by the `type` the engine reports.
    if key == FWPM_CONDITION_IP_LOCAL_INTERFACE && value.r#type == FWP_UINT64 {
        return Ok(Match::LocalInterface(unsafe { *value.Anonymous.uint64 }));
    }
    if key == FWPM_CONDITION_ALE_APP_ID && value.r#type == FWP_BYTE_BLOB_TYPE {
        if unsafe { value.Anonymous.byteBlob }.is_null() {
            return Err(foreign("a program condition with no program"));
        }
        let blob = unsafe { &*value.Anonymous.byteBlob };
        if blob.data.is_null() || blob.size == 0 {
            return Err(foreign("a program condition with no program"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
        return Ok(Match::AppId(encode_hex(bytes)));
    }
    if key == FWPM_CONDITION_ALE_USER_ID && value.r#type == FWP_SECURITY_DESCRIPTOR_TYPE {
        if unsafe { value.Anonymous.sd }.is_null()
            || unsafe { (*value.Anonymous.sd).data.is_null() }
        {
            return Err(foreign("an account condition with no account"));
        }
        let blob = unsafe { &*value.Anonymous.sd };
        let descriptor = PSECURITY_DESCRIPTOR(blob.data as *mut c_void);
        let mut text = PWSTR::null();
        // SAFETY: a descriptor the engine returned, and a valid place for the string the system allocates.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
        }
        .map_err(|_| foreign("an account that cannot be read"))?;
        // SAFETY: the system allocated a NUL-terminated string, read and then freed once.
        let sddl = unsafe { text.to_string() }.unwrap_or_default();
        unsafe { LocalFree(HLOCAL(text.0 as *mut c_void)) };
        // `D:(A;;CC;;;SY)`: the account is the last field of the one entry, and the system writes the well-known
        // ones by their two-letter names.
        let trustee = sddl.rsplit(';').next().unwrap_or("").trim_end_matches(')');
        let sid = sid_of_trustee(trustee).unwrap_or_default();
        return if is_sid_text(&sid) {
            Ok(Match::UserId(sid))
        } else {
            Err(foreign(&format!(
                "an account that is not one security identifier (the descriptor reads {sddl:?})"
            )))
        };
    }
    if key == FWPM_CONDITION_FLAGS && value.r#type == FWP_UINT32 {
        let flags = unsafe { value.Anonymous.uint32 };
        return if flags == FWP_CONDITION_FLAG_IS_LOOPBACK && c.matchType == FWP_MATCH_FLAGS_ALL_SET
        {
            Ok(Match::Loopback)
        } else {
            Err(foreign("a flags condition the guard does not use"))
        };
    }
    if key == FWPM_CONDITION_IP_PROTOCOL && value.r#type == FWP_UINT8 {
        return Ok(Match::Protocol(unsafe { value.Anonymous.uint8 }));
    }
    if key == FWPM_CONDITION_IP_LOCAL_PORT && value.r#type == FWP_UINT16 {
        return Ok(Match::LocalPort(unsafe { value.Anonymous.uint16 }));
    }
    if key == FWPM_CONDITION_IP_REMOTE_PORT && value.r#type == FWP_UINT16 {
        return Ok(Match::RemotePort(unsafe { value.Anonymous.uint16 }));
    }
    if key == FWPM_CONDITION_IP_REMOTE_ADDRESS && value.r#type == FWP_V4_ADDR_MASK {
        let v4 = unsafe { &*value.Anonymous.v4AddrMask };
        let prefix = u8::try_from(v4.mask.count_ones()).map_err(|_| foreign("a mask"))?;
        if v4.mask
            != if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            }
        {
            return Err(foreign("a mask that is not a prefix"));
        }
        return Ok(Match::RemoteV4 {
            addr: v4.addr.to_be_bytes(),
            prefix,
        });
    }
    if key == FWPM_CONDITION_IP_REMOTE_ADDRESS && value.r#type == FWP_V6_ADDR_MASK {
        let v6 = unsafe { &*value.Anonymous.v6AddrMask };
        return Ok(Match::RemoteV6 {
            addr: v6.addr,
            prefix: v6.prefixLength,
        });
    }
    let _ = from_guid; // kept for the lab's own listing
    let _: FWP_MATCH_TYPE = c.matchType;
    Err(foreign("a condition the guard does not use"))
}

/// Why the guard could not be put in.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("the guard cannot be built from this plan: {0}")]
    Plan(#[from] dnet_core::guard::GuardError),
    #[error("a rule of the guard cannot be put into the firewall's terms: {0}")]
    Translate(#[from] crate::guard_wfp::TranslateError),
    #[error("{0}")]
    Firewall(#[from] EngineError),
    #[error("the undo record could not be kept: {0}")]
    Undo(String),
    #[error("the firewall does not hold what was asked for, so the guard was taken out again: {}", .0.join("; "))]
    NotAsPlanned(Vec<String>),
    /// The firewall does not hold the plan **and** taking it out failed: the guard may still be in. This is the one
    /// outcome that needs a person: `guard-release` (or safe mode) removes it by the provider's key.
    #[error("the firewall does not hold what was asked for ({}), and the guard could not be taken out again: {removal}; it may still be in and needs to be released", .problems.join("; "))]
    StillInstalled {
        problems: Vec<String>,
        removal: String,
    },
}

/// Whether to take the guard out after an apply that failed, given whether one was in before it (`None`: could not
/// tell). The apply is one transaction, so a failure that rolled back leaves the earlier guard exactly as it was, and
/// removing it then would open the network at the moment it matters most (a restart of a connection, with the kill
/// switch on). Only a guard we are sure was not there is cleaned up, in case an ambiguous commit made one.
fn cleanup_after_failed_apply(had_guard: Option<bool>) -> bool {
    had_guard == Some(false)
}

/// Put the guard in, the way every change that can cut a computer off is made (ADR-0006 §5a):
///
/// 1. the model builds the rules from `plan` and refuses a plan that would leak;
/// 2. the undo record is **registered first**, so a crash at any point after it leaves a record that removes whatever
///    was made (and one before it leaves nothing to remove);
/// 3. the rules are applied, all or nothing;
/// 4. what the firewall holds is **read back** and compared with the plan in both directions; if it is not exactly
///    what the plan makes, the guard is taken out again and the difference is the error. A guard that is not the one
///    asked for is worse than none: it might leak, or lock the computer out.
///
/// Returns how many rules the firewall now holds.
pub fn install_guard(
    registry: &UndoRegistry,
    plan: &dnet_core::guard::GuardPlan,
) -> Result<usize, InstallError> {
    let guard = dnet_core::guard::Guard::build(plan)?;
    let translated: Vec<WfpFilter> = guard
        .filters()
        .iter()
        .map(crate::guard_wfp::to_wfp)
        .collect::<Result<_, _>>()?;
    let engine = Engine::open()?;
    let record = UndoRecord::GuardFilters {
        provider: PROVIDER_KEY.to_text(),
    };
    let had_guard = engine.is_installed().ok();
    registry
        .apply(record, || {
            if let Err(e) = engine.apply(&translated) {
                // A commit that timed out may still have landed. The record is withdrawn when this fails, so what
                // may have landed is taken out here while there is still a way to say so (review 2026-11-10,
                // finding 4), but never a guard that was in before this started (review, medium 1).
                let cleanup = if cleanup_after_failed_apply(had_guard) {
                    match engine.remove_all() {
                        Ok(()) => String::new(),
                        Err(r) => format!(
                            "; and they could not be removed again ({r}): release the guard"
                        ),
                    }
                } else {
                    "; the guard that was already in was left as it was".to_owned()
                };
                return Err(NetstateError::Operation(format!("{e}{cleanup}")));
            }
            Ok(Mutation::Applied)
        })
        .map_err(|e| InstallError::Undo(e.to_string()))?;

    let known = vec![plan.core_program.clone(), plan.service_program.clone()];
    let problems = match engine.read_back(&known) {
        Ok(held) => {
            let mut installed = Vec::with_capacity(held.len());
            let mut problems = Vec::new();
            for rule in &held {
                match crate::guard_wfp::from_wfp(rule) {
                    Ok(filter) => installed.push(filter),
                    Err(e) => problems.push(e.to_string()),
                }
            }
            problems.extend(dnet_core::guard::verify(plan, &installed));
            match engine.foreign_in_our_sublayer() {
                Ok(0) => {}
                Ok(n) => problems.push(format!(
                    "{n} filter(s) that are not the guard's sit in the guard's sublayer and can override its block"
                )),
                Err(e) => problems.push(e.to_string()),
            }
            problems
        }
        Err(e) => vec![e.to_string()],
    };
    if !problems.is_empty() {
        // Taken out again; if that fails the error says so (it must never claim a removal that did not happen), and
        // the record stays so a replay repeats it.
        return Err(match engine.remove_all() {
            Ok(()) => InstallError::NotAsPlanned(problems),
            Err(removal) => InstallError::StillInstalled {
                problems,
                removal: removal.to_string(),
            },
        });
    }
    Ok(translated.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0, 0])
            .collect()
    }

    #[test]
    fn a_program_is_trusted_only_where_the_engine_resolves_it_to_a_local_volume() {
        // Review 2026-11-10, finding 7: the syntax of a path says nothing about where it really lives.
        for ok in [
            r"\device\harddiskvolume3\program files\dnet engine\dnetd.exe",
            r"\Device\HarddiskVolume12\x.exe",
        ] {
            assert!(is_local_volume_app_id(&utf16_bytes(ok)), "{ok}");
        }
        for bad in [
            r"\device\mup\server\share\x.exe",
            r"\??\c:\x.exe",
            r"\device\harddiskvolume\x.exe",
            r"\device\harddiskvolumeshadowcopy3\x.exe",
            r"c:\x.exe",
            "",
        ] {
            assert!(!is_local_volume_app_id(&utf16_bytes(bad)), "{bad}");
        }
        assert!(!is_local_volume_app_id(&[0x5c]), "an odd number of bytes");
        assert!(!is_local_volume_app_id(&[]));
    }

    /// Review 2026-11-10: a replacement that fails must not take away a guard that was already doing its job. Only a
    /// guard we are sure was not there before is cleaned up; not knowing counts as "it was there".
    #[test]
    fn a_failed_replacement_removes_only_what_it_may_have_made() {
        assert!(cleanup_after_failed_apply(Some(false)));
        assert!(!cleanup_after_failed_apply(Some(true)));
        assert!(!cleanup_after_failed_apply(None));
    }

    #[test]
    fn only_a_security_identifier_goes_into_a_descriptor_string() {
        for ok in ["S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001", "S-1-1-0"] {
            assert!(is_sid_text(ok), "{ok}");
        }
        for bad in [
            "",
            "S-1-",
            "S-1-5-18)",
            "S-1-5-18;",
            "S-1-5--18",
            "S-1-5-18-",
            "s-1-5-18",
            "S-1-5-18 ",
            "(A;;CC;;;S-1-5-18)",
            "S-1-5-a",
        ] {
            assert!(!is_sid_text(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_trustee_is_a_full_identifier_or_a_well_known_name_and_nothing_guessed() {
        assert_eq!(sid_of_trustee("S-1-5-18").as_deref(), Some("S-1-5-18"));
        assert_eq!(sid_of_trustee("SY").as_deref(), Some("S-1-5-18"));
        assert_eq!(sid_of_trustee("BA").as_deref(), Some("S-1-5-32-544"));
        assert_eq!(sid_of_trustee("WD").as_deref(), Some("S-1-1-0"));
        assert_eq!(sid_of_trustee("AU").as_deref(), Some("S-1-5-11"));
        for unknown in ["", "ZZ", "sy", "SYS", "S-1-", "(A;;CC;;;SY)", "SY)"] {
            assert_eq!(sid_of_trustee(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(
            decode_hex(&encode_hex(&[0, 1, 0xAB, 0xFF])),
            Some(vec![0, 1, 0xAB, 0xFF])
        );
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn the_engine_error_names_the_call_and_the_code_in_hex() {
        let e = EngineError::Call {
            call: "FwpmFilterAdd0",
            code: 0x8032_0014,
        };
        assert_eq!(
            e.to_string(),
            "the firewall engine refused FwpmFilterAdd0 (0x80320014)"
        );
        assert_eq!(e.code(), Some(0x8032_0014));
        assert_eq!(EngineError::Invalid("x".into()).code(), None);
    }
}
