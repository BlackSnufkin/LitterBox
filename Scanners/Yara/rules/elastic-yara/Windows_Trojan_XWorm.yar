rule Windows_Trojan_XWorm_732e6c12 {
    meta:
        author = "Elastic Security"
        id = "732e6c12-9ee0-4d04-a6e4-9eef874e2716"
        fingerprint = "afbef8e590105e16bbd87bd726f4a3391cd6a4489f7a4255ba78a3af761ad2f0"
        creation_date = "2023-04-03"
        last_modified = "2024-10-15"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "bf5ea8d5fd573abb86de0f27e64df194e7f9efbaadd5063dee8ff9c5c3baeaa2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "startsp" ascii wide fullword
        $str2 = "injRun" ascii wide fullword
        $str3 = "getinfo" ascii wide fullword
        $str4 = "Xinfo" ascii wide fullword
        $str5 = "openhide" ascii wide fullword
        $str6 = "WScript.Shell" ascii wide fullword
        $str7 = "hidefolderfile" ascii wide fullword
    condition:
        all of them
}

rule Windows_Trojan_XWorm_b7d6eaa8 {
    meta:
        author = "Elastic Security"
        id = "b7d6eaa8-f4e6-42e6-95b2-ce67f513d6c5"
        fingerprint = "0c68cb5c8425cccc6af66c33a14e14e5f16d91835209bd38cddf38fad07a40fa"
        creation_date = "2024-09-10"
        last_modified = "2024-10-15"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "6fc4ff3f025545f7e092408b035066c1138253b972a2e9ef178e871d36f03acd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "XWorm V" wide
        $str2 = "XLogger" ascii fullword
        $str3 = "<Xwormmm>" wide fullword
        $str4 = "ActivatePong" ascii fullword
        $str5 = "ReportWindow" ascii fullword
        $str6 = "ConnectServer" ascii fullword
    condition:
        4 of them
}

rule Windows_Trojan_XWorm_7078e1c8 {
    meta:
        author = "Elastic Security"
        id = "7078e1c8-2f18-4116-8c55-e47b8e948ed7"
        fingerprint = "23304deeddcf211b7b9abc1446d8975a3ef4713e60d0363a1e1d6d69a9e5b514"
        creation_date = "2024-10-10"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "034c8a18c15521069af36595357d9c8413a33544af8d3ea5f0ac7d471841e0ec"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 72 5D 01 00 70 17 6F 29 00 00 0A 7E 21 00 00 04 28 2A 00 00 0A 09 6F 2B 00 00 0A 09 28 2C 00 00 0A 2C 0F 09 73 2D 00 00 0A 13 04 11 04 6F 2E 00 00 0A 20 E8 03 00 00 28 1F 00 00 0A }
    condition:
        all of them
}

