rule Windows_Ransomware_Ryuk_25d3c5ba : beta {
    meta:
        author = "Elastic Security"
        id = "25d3c5ba-8f80-4af0-8a5d-29c974fb016a"
        fingerprint = "18e70599e3a187e77697844fa358dd150e7e25ac74060e8c7cf2707fb7304efd"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $g1 = { 41 8B C0 45 03 C7 99 F7 FE 48 63 C2 8A 4C 84 20 }
    condition:
        1 of ($g*)
}

rule Windows_Ransomware_Ryuk_878bae7e : beta {
    meta:
        author = "Elastic Security"
        id = "878bae7e-1e53-4648-93aa-b4075eef256d"
        fingerprint = "93a501463bb2320a9ab824d70333da2b6f635eb5958d6f8de43fde3a21de2298"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b2 = "RyukReadMe.html" wide fullword
        $b3 = "RyukReadMe.txt" wide fullword
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Ryuk_6c726744 : beta {
    meta:
        author = "Elastic Security"
        id = "6c726744-acdb-443a-b683-b11f8b657f7a"
        fingerprint = "d0a4608907e48d02d78ff40a59d47cad1b9258df31b7312dd1a85f8fee2a28d5"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "172.16." ascii fullword
        $a2 = "192.168." ascii fullword
        $a3 = "DEL /F" wide fullword
        $a4 = "lsaas.exe" wide fullword
        $a5 = "delete[]" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Ransomware_Ryuk_1a4ad952 : beta {
    meta:
        author = "Elastic Security"
        id = "1a4ad952-cc99-4653-932b-290381e7c871"
        fingerprint = "d8c5162850e758e27439e808e914df63f42756c0b8f7c2b5f9346c0731d3960c"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $e1 = { 8B 0A 41 8D 45 01 45 03 C1 48 8D 52 08 41 3B C9 41 0F 45 C5 44 8B E8 49 63 C0 48 3B C3 72 E1 }
    condition:
        1 of ($e*)
}

rule Windows_Ransomware_Ryuk_72b5fd9d : beta {
    meta:
        author = "Elastic Security"
        id = "72b5fd9d-23db-4f18-88d9-a849ec039135"
        fingerprint = "7c394aa283336013b74a8aaeb56e8363033958b4a1bd8011f3b32cfe2d37e088"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Ryuk_8ba51798 : beta {
    meta:
        author = "Elastic Security"
        id = "8ba51798-15d7-4f02-97fa-1844465ae9d8"
        fingerprint = "8e284bc6015502577a6ddd140b9cd110fd44d4d2cb55d0fdec5bebf3356fd7b3"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = "/v \"svchos\" /f" wide fullword
        $c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
        $c3 = "lsaas.exe" wide fullword
        $c4 = "FA_Scheduler" wide fullword
        $c5 = "ocautoupds" wide fullword
        $c6 = "CNTAoSMgr" wide fullword
        $c7 = "hrmlog" wide fullword
        $c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword
    condition:
        3 of ($c*)
}

rule Windows_Ransomware_Ryuk_88daaf8e : beta {
    meta:
        author = "Elastic Security"
        id = "88daaf8e-0bfe-46c4-9a75-2527d0e10538"
        fingerprint = "b1f218a9bc6bf5f3ec108a471de954988e7692de208e68d7d4ee205194cbbb40"
        creation_date = "2020-04-30"
        last_modified = "2021-08-23"
        description = "Identifies RYUK ransomware"
        threat_name = "Windows.Ransomware.Ryuk"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $f1 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }
    condition:
        1 of ($f*)
}

