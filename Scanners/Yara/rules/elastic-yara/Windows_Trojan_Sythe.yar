rule Windows_Trojan_Sythe_02b2811a {
    meta:
        author = "Elastic Security"
        id = "02b2811a-2ced-42b6-a9f1-6d983d1dc986"
        fingerprint = "4dd9764e285985fbea5361e5edfa04e75fb8e3e7945cbbf712ea0183471e67ae"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Sythe"
        reference_sample = "2d54a8ba40cc9a1c74db7a889bc75a38f16ae2d025268aa07851c1948daa1b4d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "loadmodule"
        $a2 = "--privileges"
        $a3 = "--shutdown"
        $a4 = "SetClientThreadID"
    condition:
        all of them
}

