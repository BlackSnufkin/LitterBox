rule Windows_Trojan_TwistedTinsel_aa56e527 {
    meta:
        author = "Elastic Security"
        id = "aa56e527-df1a-4db7-ad89-187dff5e8745"
        fingerprint = "e78a92c34ce7ab5545cd44930839551f72d8b19256d4f3280aad81358233f9eb"
        creation_date = "2023-12-06"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.TwistedTinsel"
        reference_sample = "ef1cbdf9a23ae028a858e1d09529982eaeda61197ae029e091918690d3a86e2e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 3A 5C 50 72 6F 67 72 61 6D 44 61 74 61 5C 4D 69 63 72 6F 73 6F 66 74 5C 45 64 67 65 55 70 64 61 74 65 5C 4C 6F 67 5C 63 68 75 61 6E 67 6B 6F 75 2E 6C 6F 67 }
        $a2 = { 55 8B EC 83 EC 20 C7 45 EC 01 00 00 00 8B 45 08 8B 48 04 89 4D F4 8B 55 08 8B 02 B9 08 00 00 00 C1 E1 00 8D 54 08 78 89 55 E4 8B 45 E4 83 78 04 00 0F 86 81 01 00 00 8B 4D E4 8B 55 F4 03 11 89 }
    condition:
        any of them
}

