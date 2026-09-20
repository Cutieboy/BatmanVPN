!include "LogicLib.nsh"

; Migrate the legacy MouseVPN Windows installation to BatmanVPN while
; preserving application data and VPN profiles.
!macro NSIS_HOOK_PREINSTALL
  ReadRegStr $R2 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\MouseVPN" "UninstallString"
  ${If} $R2 != ""
    DetailPrint "Удаление предыдущей версии MouseVPN..."
    ExecWait '$R2 /S' $R3
    ${If} $R3 != 0
      MessageBox MB_ICONSTOP|MB_OK "Не удалось удалить предыдущую версию MouseVPN (код $R3). Профили не затронуты. Закройте MouseVPN и повторите установку BatmanVPN."
      SetErrorLevel 6
      Quit
    ${EndIf}
  ${EndIf}
!macroend
