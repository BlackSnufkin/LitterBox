rule Windows_Trojan_CyberGate_517aac7d {
    meta:
        author = "Elastic Security"
        id = "517aac7d-2737-4917-9aa1-c0bd1c3e9801"
        fingerprint = "3d998bda8e56de6fd6267abdacffece8bcf1c62c2e06540a54244dc6ea816825"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "IELOGIN.abc" ascii fullword
        $a2 = "xxxyyyzzz.dat" ascii fullword
        $a3 = "_x_X_PASSWORDLIST_X_x_" ascii fullword
        $a4 = "L$_RasDefaultCredentials#0" ascii fullword
        $a5 = "\\signons1.txt" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_CyberGate_9996d800 {
    meta:
        author = "Elastic Security"
        id = "9996d800-a833-4535-972b-3ee320215bb6"
        fingerprint = "eb39d2ff211230aedcf1b5ec0d1dfea108473cc7cba68f5dc1a88479734c02b0"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 08 8B 44 24 08 83 C4 14 5D 5F 5E 5B C3 55 8B EC 83 C4 F0 }
    condition:
        all of them
}

rule Windows_Trojan_CyberGate_c219a2f3 {
    meta:
        author = "Elastic Security"
        id = "c219a2f3-5ae2-4cdf-97d7-2778954ee826"
        fingerprint = "8a79d1eba89dd08d2e8bdedee834c88dbeabf5f2f249b1e5accdb827671c22c2"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.CyberGate"
        reference_sample = "b7204f8caf6ace6ae1aed267de0ad6b39660d0e636d8ee0ecf88135f8a58dc42"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 00 55 8B EC 83 C4 EC 56 57 8B 45 08 8B F0 8D 7D EC A5 A5 }
        $a2 = { 49 80 39 C3 75 F5 8B C2 C3 55 8B EC 6A 00 6A 00 6A 00 53 56 57 }
    condition:
        all of them
}

