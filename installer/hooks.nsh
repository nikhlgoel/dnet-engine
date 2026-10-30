; T114 - what the DNet Engine installer adds to the Tauri NSIS template (bundle > windows > nsis >
; installerHooks, in installer/tauri.installer.json). Checked against the template in @tauri-apps/cli
; 2.12.2: PREINSTALL runs in "Section Install" before the window's files are copied, POSTINSTALL after
; the shortcuts, PREUNINSTALL first in "Section Uninstall"; $UpdateMode and $DeleteAppDataCheckboxState
; are the template's own variables.
;
; The payload comes from `cargo xtask stage-installer` (target\payload). Files are named here only by
; folder or wildcard: the service, the cores and the adapter library all go to the install folder,
; beside each other, which is the layout dnetd and its start-up recovery depend on.
;
; The service registers and removes itself (`dnetd install` / `dnetd uninstall`), so the checks that
; matter (an install folder ordinary users cannot change, a private data folder, the network restored
; before the service is removed) live in tested Rust, not here.

!define DNET_PAYLOAD "${__FILEDIR__}\..\target\payload"
!define DNET_RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

!macro NSIS_HOOK_PREINSTALL
  ; An upgrade over a running service: stop it so its files can be replaced. It takes its tunnel down
  ; first, and comes back connected if it was left on.
  ${If} ${FileExists} "$INSTDIR\dnetd.exe"
    nsExec::ExecToLog '"$INSTDIR\dnetd.exe" stop'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "The running DNet Engine service could not be stopped, so it cannot be updated. Restart Windows and run this installer again." /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
  SetOutPath "$INSTDIR"
  File "${DNET_PAYLOAD}\app\*.*"
  SetOutPath "$INSTDIR\licences"
  File /r "${DNET_PAYLOAD}\licences\*.*"
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog '"$INSTDIR\dnetd.exe" install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The DNet Engine service could not be set up (code $0). The installer's details list the reason. This computer's network settings were not changed." /SD IDOK
    Abort
  ${EndIf}
  ; The tray for everyone who signs in. It holds no privilege: the service does the work, and keeps
  ; doing it whether or not the tray is running.
  WriteRegStr HKLM "${DNET_RUN_KEY}" "${PRODUCTNAME}" '"$INSTDIR\${MAINBINARYNAME}.exe"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; The service first: it restores the network before it is removed, and refuses to be removed if it
  ; cannot, so an uninstall never leaves this computer with a route or name server nobody will undo.
  ${If} ${FileExists} "$INSTDIR\dnetd.exe"
    ${If} $DeleteAppDataCheckboxState = 1
    ${AndIf} $UpdateMode <> 1
      nsExec::ExecToLog '"$INSTDIR\dnetd.exe" uninstall --remove-settings'
    ${Else}
      nsExec::ExecToLog '"$INSTDIR\dnetd.exe" uninstall'
    ${EndIf}
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "DNet Engine could not restore this computer's network settings, so it was not removed. Restart Windows and try again." /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
  Delete "$INSTDIR\dnetd.exe"
  Delete "$INSTDIR\dnetctl.exe"
  Delete "$INSTDIR\primary-core.exe"
  Delete "$INSTDIR\amneziawg-go.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\server-pins.json"
  RMDir /r "$INSTDIR\licences"
  ${If} $UpdateMode <> 1
    DeleteRegValue HKLM "${DNET_RUN_KEY}" "${PRODUCTNAME}"
  ${EndIf}
!macroend
