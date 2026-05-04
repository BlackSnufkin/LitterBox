rule Multi_Hacktool_Stowaway_89f1d452 {
    meta:
        author = "Elastic Security"
        id = "89f1d452-f40b-47da-ba75-10c90d67c13b"
        fingerprint = "313e22009ad758c0dd0977c274eb165511591e3d99a8e2dd4be00622668981da"
        creation_date = "2024-06-28"
        last_modified = "2024-07-26"
        threat_name = "Multi.Hacktool.Stowaway"
        reference_sample = "c073d3be469c8eea0f007bb37c722bad30e06dc994d3a59773838ed8be154c95"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Stowaway/share.ActivePreAuth" ascii fullword
        $a2 = "Stowaway/agent/handler" ascii fullword
        $a3 = "Origin: http://stowaway:22" ascii fullword
        $a4 = "Stowaway/admin.NewAdmin" ascii fullword
        $a5 = "Stowaway/global/global.go" ascii fullword
        $a6 = "Stowaway/crypto.AESDecrypt" ascii fullword
        $a7 = "Stowaway/utils.CheckIfIP4" ascii fullword
        $a8 = "Exit Stowaway"
        $a9 = "Stowaway/protocol.ConstructMessage" ascii fullword
    condition:
        3 of them
}

