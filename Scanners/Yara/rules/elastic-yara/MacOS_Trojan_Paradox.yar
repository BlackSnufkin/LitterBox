rule MacOS_Trojan_Paradox_563594b2 {
    meta:
        author = "Elastic Security"
        id = "563594b2-19a8-4498-91dd-b400224a0a62"
        fingerprint = "4f3e5d923524d070c1df4852a4ead59a3819d61c3f9b996fbabd9fb5eb038da8"
        creation_date = "2026-02-26"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.Paradox"
        reference_sample = "da19644b4ad68ac77fa4ed4e6254dbf4e6d2a5cdb438666b3f36c5edb46ae986"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a_0 = "paradox_payload/extraction.CollectSystemInfo"
        $a_1 = "paradox_payload/discovery.CheckKeychainDirectories"
        $a_2 = "paradox_payload/discovery.CheckCryptoDirectories"
        $a_3 = "paradox_payload/extraction.GetIPInfo"
        $b = { FD 23 00 D1 E1 6B 02 F9 E0 67 02 F9 FB 23 12 91 7F 7F 00 A9 }
    condition:
        all of ($a_*) or $b
}

