rule Windows_Trojan_RudeBird_3cbf7bc6 {
    meta:
        author = "Elastic Security"
        id = "3cbf7bc6-71c5-4c7c-a846-7a95c3d28917"
        fingerprint = "f70bd86d877d9371601c7f65cf50a5bb9b76ba45acbf591bd8e4c1117a0cac1d"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RudeBird"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 40 53 48 83 EC 20 48 8B D9 B9 D8 00 00 00 E8 FD C1 FF FF 48 8B C8 33 C0 48 85 C9 74 05 E8 3A F2 }
    condition:
        all of them
}

