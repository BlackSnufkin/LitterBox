rule Linux_Trojan_Shellbot_65aa6568 {
    meta:
        author = "Elastic Security"
        id = "65aa6568-491a-4a51-b921-c6c228cfca11"
        fingerprint = "2cd606ecaf17322788a5ee3b6bd663bed376cef131e768bbf623c402664e9270"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Shellbot"
        reference_sample = "457d1f4e1db41a9bdbfad78a6815f42e45da16ad0252673b9a2b5dcefc02c47b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 00 73 74 72 63 6D 70 00 70 61 6D 5F 70 72 6F 6D 70 74 00 }
    condition:
        all of them
}

