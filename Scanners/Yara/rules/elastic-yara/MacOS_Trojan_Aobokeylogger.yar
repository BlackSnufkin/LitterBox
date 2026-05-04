rule MacOS_Trojan_Aobokeylogger_bd960f34 {
    meta:
        author = "Elastic Security"
        id = "bd960f34-1932-41be-ac0a-f45ada22c560"
        fingerprint = "ae26a03d1973669cbeaabade8f3fd09ef2842b9617fa38e7b66dc4726b992a81"
        creation_date = "2021-10-18"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Aobokeylogger"
        reference_sample = "2b50146c20621741642d039f1e3218ff68e5dbfde8bb9edaa0a560ca890f0970"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 20 74 68 61 6E 20 32 30 30 20 6B 65 79 73 74 72 6F 6B 65 73 20 }
    condition:
        all of them
}

