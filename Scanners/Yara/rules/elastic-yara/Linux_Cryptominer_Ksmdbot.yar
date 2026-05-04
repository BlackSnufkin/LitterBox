rule Linux_Cryptominer_Ksmdbot_ebeedb3c {
    meta:
        author = "Elastic Security"
        id = "ebeedb3c-adc3-4df8-a8bf-5120802fa3c2"
        fingerprint = "c6b678a94e45441ef960bc7119e2b9742ce8aab7e463897bf4a14aa0c57d507c"
        creation_date = "2022-12-14"
        last_modified = "2024-02-13"
        threat_name = "Linux.Cryptominer.Ksmdbot"
        reference_sample = "b927e0fe58219305d86df8b3e44493a7c854a6ea4f76d1ebe531a7bfd4365b54"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 BA 74 63 70 66 69 76 65 6D 4? 8B ?? 24 }
        $a2 = { 48 B9 FF FF FF FF 67 65 74 73 48 89 08 48 B9 65 74 73 74 61 74 75 73 48 89 48 }
        $a3 = { 48 B? 73 74 61 72 74 6D 69 6E 49 39 ?3 }
        $a4 = { 48 BA 6C 6F 61 64 63 6C 69 65 48 8B B4 24 }
        $a5 = { 48 BA 73 74 6? 7? 7? 6? 6? 6E 49 39 13 }
    condition:
        3 of them
}

