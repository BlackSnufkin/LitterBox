rule Windows_Ransomware_Cicada3301_99fee259 {
    meta:
        author = "Elastic Security"
        id = "99fee259-6633-40f9-824b-49a7aa692753"
        fingerprint = "d1bf61f2bf824f8620db6862efa45a0b32266da6de658fad8c81cba347cb2080"
        creation_date = "2024-09-05"
        last_modified = "2024-09-30"
        threat_name = "Windows.Ransomware.Cicada3301"
        reference_sample = "7b3022437b637c44f42741a92c7f7ed251845fd02dda642c0a47fde179bd984e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "sqldocrtfxlsjpgjpegpnggifwebptiffpsdrawbmppdfdocxdocmdotxdotmodtxlsxxlsmxltxxltmxlsbx"
        $a2 = "keypathhelpsleepno_implno_localno_netno_notesno_iconno_desktop" ascii fullword
        $a3 = "RECOVER--DATA.txt" ascii fullword
        $a4 = "CMD_BCDEDIT_SET_RECOVERY_DISABLED"
        $a5 = "CMD_WMIC_SHADOWCOPY_DELETE"
    condition:
        2 of them
}

