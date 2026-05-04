rule Windows_Hacktool_Dcsyncer_425579c5 {
    meta:
        author = "Elastic Security"
        id = "425579c5-496f-4e08-a7e3-bf56e622aa21"
        fingerprint = "f6a0c028323be41f6ec90af8a7ea8587fee6985ddefdbcdd24351cb615f756a2"
        creation_date = "2021-09-15"
        last_modified = "2022-01-13"
        description = "MGIxY2/05+FBDTur++++0OUs"
        threat_name = "Windows.Hacktool.Dcsyncer"
        reference_sample = "af7dbc84efeb186006d75d095f54a266f59e6b2348d0c20591da16ae7b7d509a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[x] dcsync: Error in ProcessGetNCChangesReply" wide fullword
        $a2 = "[x] getDCBind: RPC Exception 0x%08x (%u)" wide fullword
        $a3 = "[x] getDomainAndUserInfos: DomainControllerInfo: 0x%08x (%u)" wide fullword
        $a4 = "[x] ProcessGetNCChangesReply_decrypt: Checksums don't match (C:0x%08x - R:0x%08x)" wide fullword
    condition:
        any of them
}

