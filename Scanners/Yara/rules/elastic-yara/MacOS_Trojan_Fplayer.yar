rule MacOS_Trojan_Fplayer_1c1fae37 {
    meta:
        author = "Elastic Security"
        id = "1c1fae37-8d19-4129-a715-b78163f93fd2"
        fingerprint = "abeb3cd51c0ff2e3173739c423778defb9a77bc49b30ea8442e6ec93a2d2d8d2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Fplayer"
        reference_sample = "f57e651088dee2236328d09705cef5e98461e97d1eb2150c372d00ca7c685725"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 56 41 55 41 54 53 48 83 EC 48 4D 89 C4 48 89 C8 48 89 D1 49 89 F6 49 89 FD 49 }
    condition:
        all of them
}

