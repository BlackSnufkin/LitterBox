rule Macos_Infostealer_Atomic_94ac4578 {
    meta:
        author = "Elastic Security"
        id = "94ac4578-2514-4331-ada9-5a63cd833cc3"
        fingerprint = "b07afdfb657a5f22ef6ee23b5ee3b9b2822911fad03fe33a7fec5d2038092687"
        creation_date = "2024-03-06"
        last_modified = "2024-04-06"
        threat_name = "Macos.Infostealer.Atomic"
        reference_sample = "bafd232300548838af32b72443ed44c8ed63e840d0726c3c10e9b6d73d179165"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = { 5F 00 5F 5F 5A 34 68 6D 6D 6D 76 00 5F 5F 5A 4E 53 74 33 5F 5F 31 70 6C }
        $s2 = { 48 6F 73 74 3A 50 4F 53 54 20 2F 6A 6F 69 6E 73 79 73 74 65 6D 64 }
        $s3 = "dscl /Local/Defa/password-enterens/login.keychai/Library"
        $s4 = "fNS40Mi42NS4xMDc= HTTP/1.1"
        $s5 = "efcagfbpxyzvshakagqgrahpjgtf/Build"
    condition:
        any of them
}

