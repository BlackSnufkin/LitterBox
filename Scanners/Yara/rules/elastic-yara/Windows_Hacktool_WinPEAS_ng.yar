rule Windows_Hacktool_WinPEAS_ng_66197d54 {
    meta:
        author = "Elastic Security"
        id = "66197d54-3cd2-4006-807d-24d0e0d9e25a"
        fingerprint = "951f0ca036a0ab0cf2299382049eecb78f35325470f222c6db90a819b9414083"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, application module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Possible DLL Hijacking, folder is writable" ascii wide
        $win_1 = "FolderPerms:.*" ascii wide
        $win_2 = "interestingFolderRights" ascii wide
        $win_3 = "(Unquoted and Space detected)" ascii wide
        $win_4 = "interestingFolderRights" ascii wide
        $win_5 = "RegPerms: .*" ascii wide
        $win_6 = "Permissions file: {3}" ascii wide
        $win_7 = "Permissions folder(DLL Hijacking):" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_e8ed269c {
    meta:
        author = "Elastic Security"
        id = "e8ed269c-3191-44c0-a9c6-55172fb59c8c"
        fingerprint = "7b6ede4d95b2d6d2a43e729365adb9de3fde74ed731cafdb88916ac3925f9164"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, checks module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "systeminfo" ascii wide
        $win_1 = "Please specify a valid log file." ascii wide
        $win_2 = "argument present, redirecting output" ascii wide
        $win_3 = "max-regex-file-size" ascii wide
        $win_4 = "-lolbas" ascii wide
        $win_5 = "[!] the provided linpeas.sh url:" ascii wide
        $win_6 = "sensitive_files yaml" ascii wide
        $win_7 = "Getting Win32_UserAccount" ascii wide
        $win_8 = "(local + domain)" ascii wide
        $win_9 = "Creating AppLocker bypass" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_413caa6b {
    meta:
        author = "Elastic Security"
        id = "413caa6b-90b7-4763-97b3-49aeb5a97cf6"
        fingerprint = "80b32022a69be8fc1d7e146c3c03623b51e2ee4206eb5f70be753477d68800d5"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, event module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Interesting Events information" ascii wide
        $win_1 = "PowerShell events" ascii wide
        $win_2 = "Created (UTC)" ascii wide
        $win_3 = "Printing Account Logon Events" ascii wide
        $win_4 = "Subject User Name" ascii wide
        $win_5 = "Target User Name" ascii wide
        $win_6 = "NTLM relay might be possible" ascii wide
        $win_7 = "You can obtain NetNTLMv2" ascii wide
        $win_8 = "The following users have authenticated" ascii wide
        $win_9 = "You must be an administrator" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_23fee092 {
    meta:
        author = "Elastic Security"
        id = "23fee092-f1ff-4d9e-9873-0a68360efb42"
        fingerprint = "4420faa4da440a9e2b1d8eadef2a1864c078fccf391ac3d7872abe1d738c926e"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, File analysis module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "File Analysis" ascii wide
        $win_1 = "apache*" ascii wide
        $win_2 = "tomcat*" ascii wide
        $win_3 = "had a timeout (ReDoS avoided but regex" ascii wide
        $win_4 = "Error looking for regex" ascii wide
        $win_5 = "Looking for secrets inside" ascii wide
        $win_6 = "files with ext" ascii wide
        $win_7 = "(limited to" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_861d3264 {
    meta:
        author = "Elastic Security"
        id = "861d3264-34c3-4ff0-bdd3-44cb5ecce2c8"
        fingerprint = "03803621b6c9856443809889a14f1d2fa217812007878dd6cf9c3dc9e5f78f65"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, File Info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "ConsoleHost_history.txt" ascii wide
        $win_1 = "Interesting files and registry" ascii wide
        $win_2 = "Cloud Credentials" ascii wide
        $win_3 = "Accessed:{2} -- Size:{3}" ascii wide
        $win_4 = "Unattend Files" ascii wide
        $win_5 = "Looking for common SAM" ascii wide
        $win_6 = "Found installed WSL distribution" ascii wide
        $win_7 = "Check skipped, if you want to run it" ascii wide
        $win_8 = "Cached GPP Passwords" ascii wide
        $win_9 = "[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[pP][aA][sS][sS][wW][oO]" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_57587f8c {
    meta:
        author = "Elastic Security"
        id = "57587f8c-8fc6-41cc-bcb3-3d1d77c74222"
        fingerprint = "9938c60113963da342dcb7de2252cffbeaa21d36f518e203f19a43da74d85f2d"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, Network module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Network Information" ascii wide
        $win_1 = "Network Shares" ascii wide
        $win_2 = "Permissions.*" ascii wide
        $win_3 = "Network Ifaces and known hosts" ascii wide
        $win_4 = "Enumerating IPv4 connections" ascii wide
        $win_5 = "Showing only DENY rules" ascii wide
        $win_6 = "File Permissions.*|Folder Permissions.*" ascii wide
        $win_7 = "DNS cached --limit" ascii wide
        $win_8 = "SELECT * FROM win32_networkconnection" ascii wide
        $win_9 = "Enumerating Internet settings," ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_cae025b1 {
    meta:
        author = "Elastic Security"
        id = "cae025b1-bc2a-4eea-a1c1-c82d6e4fd71f"
        fingerprint = "3e407824b258ef66ac6883d4c5dd3efeb0f744f8f64b099313cf83e96f9e968a"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, Process info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Processes Information" ascii wide
        $win_1 = "Interesting Processes -non Microsoft-" ascii wide
        $win_2 = "Permissions:.*" ascii wide
        $win_3 = "Possible DLL Hijacking.*" ascii wide
        $win_4 = "ExecutablePath" ascii wide
        $win_5 = "Vulnerable Leaked Handlers" ascii wide
        $win_6 = "Possible DLL Hijacking folder:" ascii wide
        $win_7 = "Command Line:" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_4a9b9603 {
    meta:
        author = "Elastic Security"
        id = "4a9b9603-7b42-4a85-b66a-7f4ec0013338"
        fingerprint = "2a7b0e1d850fa6a24f590755ae5610309741e520e4b2bc067f54a8e086444da2"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, Services info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Services Information" ascii wide
        $win_1 = "Interesting Services -non Microsoft-" ascii wide
        $win_2 = "FilteredPath" ascii wide
        $win_3 = "YOU CAN MODIFY THIS SERVICE:" ascii wide
        $win_4 = "Modifiable Services" ascii wide
        $win_5 = "AccessSystemSecurity" ascii wide
        $win_6 = "Looks like you cannot change the" ascii wide
        $win_7 = "Checking write permissions in" ascii wide
    condition:
        4 of them
}

rule Windows_Hacktool_WinPEAS_ng_4db2c852 {
    meta:
        author = "Elastic Security"
        id = "4db2c852-6c03-4672-9250-f80671b93e1b"
        fingerprint = "f05862b7b74cb4741aa953d725336005cdb9b1d50a92ce8bb295114e27f81b2a"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, System info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "No prompting|PromptForNonWindowsBinaries" ascii wide
        $win_1 = "System Information" ascii wide
        $win_2 = "Showing All Microsoft Updates" ascii wide
        $win_3 = "GetTotalHistoryCount" ascii wide
        $win_4 = "PS history size:" ascii wide
        $win_5 = "powershell_transcript*" ascii wide
        $win_6 = "Check what is being logged" ascii wide
        $win_7 = "WEF Settings" ascii wide
        $win_8 = "CredentialGuard is active" ascii wide
        $win_9 = "cachedlogonscount is" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_bcedc8b2 {
    meta:
        author = "Elastic Security"
        id = "bcedc8b2-d9e1-45cd-94b4-a19a3ed8c0f9"
        fingerprint = "039ea2f11596d6a8d5da05944796424ee6be66e16742676bbb2dc3fcf274cf4a"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, User info module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Users Information" ascii wide
        $win_1 = "docker|Remote |DNSAdmins|AD Recycle Bin|" ascii wide
        $win_2 = "NotChange|NotExpi" ascii wide
        $win_3 = "Current Token privileges" ascii wide
        $win_4 = "Clipboard text" ascii wide
        $win_5 = "{0,-10}{1,-15}{2,-15}{3,-25}{4,-10}{5}" ascii wide
        $win_6 = "Ever logged users" ascii wide
        $win_7 = "Some AutoLogon credentials were found" ascii wide
        $win_8 = "Current User Idle Time" ascii wide
        $win_9 = "DsRegCmd.exe /status" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_b6bb3e7c {
    meta:
        author = "Elastic Security"
        id = "b6bb3e7c-29f6-4bc6-8082-558a56512fc3"
        fingerprint = "ecc2217349244cd78fa5be040653c02096ee8b6a2f2691309fd7f9f62612fa79"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the dotNet binary, Windows credentials module"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Windows Credentials" ascii wide
        $win_1 = "Checking Windows Vault" ascii wide
        $win_2 = "Identity.*|Credential.*|Resource.*" ascii wide
        $win_3 = "Checking Credential manager" ascii wide
        $win_4 = "Saved RDP connections" ascii wide
        $win_5 = "Recently run commands" ascii wide
        $win_6 = "Checking for DPAPI" ascii wide
        $win_7 = "Checking for RDCMan" ascii wide
        $win_8 = "Looking for saved Wifi credentials" ascii wide
        $win_9 = "Looking AppCmd.exe" ascii wide
    condition:
        5 of them
}

rule Windows_Hacktool_WinPEAS_ng_94474b0b {
    meta:
        author = "Elastic Security"
        id = "94474b0b-c3dc-4585-afb3-3afe4c3ec525"
        fingerprint = "06e184fb837274271711288994a3e6bfcc2a50472ca05c8af9f1e4d8efd9091d"
        creation_date = "2022-12-21"
        last_modified = "2023-02-01"
        description = "WinPEAS detection based on the bat script"
        threat_name = "Windows.Hacktool.WinPEAS-ng"
        reference_sample = "f3e1e5b6fd2d548dfe0af8730b15eb7ef40e128a0777855f569b2a99d6101195"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $win_0 = "Windows local Privilege Escalation Awesome Script" ascii wide
        $win_1 = "BASIC SYSTEM INFO" ascii wide
        $win_2 = "LAPS installed?" ascii wide
        $win_3 = "Check for services restricted from the outside" ascii wide
        $win_4 = "CURRENT USER" ascii wide
        $win_5 = "hacktricks.xyz" ascii wide
        $win_6 = "SERVICE VULNERABILITIES" ascii wide
        $win_7 = "DPAPI MASTER KEYS" ascii wide
        $win_8 = "Files in registry that may contain credentials" ascii wide
        $win_9 = "SAM and SYSTEM backups" ascii wide
    condition:
        6 of them
}

