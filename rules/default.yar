// Basic Antivirus Simulation - detection rules (YARA-like syntax, see av/rules.py)
// Every rule is mapped to a MITRE ATT&CK technique.

rule EICAR_Test_String {
    meta:
        description = "EICAR antivirus test string (harmless test file)"
        severity = "high"
        mitre = "TEST"
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $a
}

rule PowerShell_Download_Cradle {
    meta:
        description = "Script that downloads content from the internet"
        severity = "medium"
        mitre = "T1059.001"
    strings:
        $a = "DownloadString" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "Net.WebClient" nocase
        $d = "DownloadFile" nocase
    condition:
        2 of them
}

rule PowerShell_Encoded_Command {
    meta:
        description = "PowerShell started with a hidden, encoded command"
        severity = "medium"
        mitre = "T1027"
    strings:
        $a = /powershell[^\n]{0,80}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/i
    condition:
        $a
}

rule Process_Injection_APIs {
    meta:
        description = "Windows API names used to inject code into other processes"
        severity = "high"
        mitre = "T1055"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
    condition:
        2 of them
}

rule Keylogger_APIs {
    meta:
        description = "API names used to capture keystrokes"
        severity = "medium"
        mitre = "T1056.001"
    strings:
        $a = "GetAsyncKeyState"
        $b = "SetWindowsHookEx"
        $c = "GetKeyboardState"
    condition:
        2 of them
}

rule Registry_Run_Key_Persistence {
    meta:
        description = "Writes a program into the Windows Run key to start at logon"
        severity = "medium"
        mitre = "T1547.001"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
    condition:
        $a
}

rule Shadow_Copy_Deletion {
    meta:
        description = "Deletes Windows backups, typical before ransomware encryption"
        severity = "high"
        mitre = "T1490"
    strings:
        $a = "vssadmin" nocase
        $b = "delete shadows" nocase
        $c = "shadowcopy delete" nocase
    condition:
        $a and ($b or $c)
}

rule Ransom_Note_Text {
    meta:
        description = "Text typical of a ransom note"
        severity = "high"
        mitre = "T1486"
    strings:
        $a = "files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
    condition:
        $a and ($b or $c)
}

rule UPX_Packer_Sections {
    meta:
        description = "Program packed with UPX (hides its real code)"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $a = "UPX0"
        $b = "UPX1"
    condition:
        all of them
}

rule Windows_Executable_Header {
    meta:
        description = "File starts with a Windows executable header (informational)"
        severity = "low"
        mitre = "T1204.002"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Webhook_Exfiltration {
    meta:
        description = "Sends data to a chat webhook, a common exfiltration channel"
        severity = "medium"
        mitre = "T1567"
    strings:
        $a = "discord.com/api/webhooks" nocase
        $b = "api.telegram.org/bot" nocase
    condition:
        any of them
}

rule Credential_Dumping_Strings {
    meta:
        description = "Strings linked to dumping Windows credentials from memory"
        severity = "high"
        mitre = "T1003.001"
    strings:
        $a = "lsass" nocase
        $b = "MiniDumpWriteDump"
        $c = "sekurlsa" nocase
    condition:
        $a and ($b or $c)
}
