rule Windows_Trojan_Matanbuchus_b521801b {
    meta:
        author = "Elastic Security"
        id = "b521801b-5623-4bfe-9a9d-9e16afa63c63"
        fingerprint = "7792cffc82678bb05ba1aa315011317611eb0bf962665e0657a7db2ce95f81b4"
        creation_date = "2022-03-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%PROCESSOR_ARCHITECTURE%" ascii fullword
        $a2 = "%PROCESSOR_REVISION%\\" ascii fullword
        $a3 = "%LOCALAPPDATA%\\" ascii fullword
        $a4 = "\"C:\\Windows\\system32\\schtasks.exe\" /Create /SC MINUTE /MO 1 /TN" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Matanbuchus_4ce9affb {
    meta:
        author = "Elastic Security"
        id = "4ce9affb-58ef-4d31-b1ff-5a1c52822a01"
        fingerprint = "61d32df2ea730343ab497f50d250712e89ec942733c8cc4421083a3823ab9435"
        creation_date = "2022-03-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { F4 83 7D F4 00 77 43 72 06 83 7D F0 11 73 3B 6A 00 6A 01 8B }
    condition:
        all of them
}

rule Windows_Trojan_Matanbuchus_c7811ccc {
    meta:
        author = "Elastic Security"
        id = "c7811ccc-5d8d-4bc8-a630-ac3282bb207e"
        fingerprint = "05f209a24d9eb2be7fa50444d8271b6f147027291f55a352ac3af5e9b3207010"
        creation_date = "2022-03-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Matanbuchus"
        reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 08 53 56 0F 57 C0 66 0F 13 45 F8 EB ?? 8B 45 F8 83 C0 01 8B 4D FC 83 D1 00 89 45 F8 89 4D FC 8B 55 FC 3B 55 10 77 ?? 72 ?? 8B 45 F8 3B 45 0C 73 ?? 6A 00 6A 08 8B 4D FC 51 8B 55 F8 52 E8 ?? ?? ?? ?? 6A 00 6A 08 52 50 E8 ?? ?? ?? ?? 8B C8 8B 45 14 8B 55 18 E8 ?? ?? ?? ?? 0F BE F0 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 0F BE 1C 01 33 DE 6A 00 6A 01 8B 55 FC 52 8B 45 F8 50 E8 ?? ?? ?? ?? 8B 4D 08 88 1C 01 E9 ?? ?? ?? ?? 5E 5B 8B E5 5D C2 14 00 }
    condition:
        all of them
}

