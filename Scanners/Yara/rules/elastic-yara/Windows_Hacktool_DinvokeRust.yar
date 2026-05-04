rule Windows_Hacktool_DinvokeRust_512d3b59 {
    meta:
        author = "Elastic Security"
        id = "512d3b59-6bd3-4716-aa5f-1541044bbf9a"
        fingerprint = "0587368dc33b7fee0037be9247daaeaf6846c2b4a839660511ebf5eb0fdfb087"
        creation_date = "2024-02-28"
        last_modified = "2024-03-21"
        threat_name = "Windows.Hacktool.DinvokeRust"
        reference_sample = "ebf0f1bfd166d2d49b642fa43cb0c7364c0c605d9a7f108dc49d9f1cc859ab4a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = { 64 69 6E 76 6F 6B 65 ?? ?? 67 65 74 5F }
        $s2 = { 64 69 6E 76 6F 6B 65 ?? ?? 6E 74 5F }
        $s3 = { 64 69 6E 76 6F 6B 65 ?? ?? 6C 69 74 63 72 79 70 74 }
        $s4 = { 64 69 6E 76 6F 6B 65 5C 73 72 63 5C 6C 69 62 2E 72 73 }
        $s5 = { 75 6E 77 69 6E 64 65 72 ?? ?? 63 61 6C 6C 5F 66 75 6E 63 74 69 6F 6E }
        $s6 = { 75 6E 77 69 6E 64 65 72 ?? ?? 69 6E 64 69 72 65 63 74 5F 73 79 73 63 61 6C 6C }
    condition:
        2 of them
}

