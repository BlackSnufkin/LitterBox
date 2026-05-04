rule Multi_Trojan_Goffloader_d1f4201e {
    meta:
        author = "Elastic Security"
        id = "d1f4201e-74ce-4f72-a661-47c2fb993623"
        fingerprint = "f8457fca4d8307639839199ef5fd01c8a5ad425dd341b3a5f8e5a6a9fad16329"
        creation_date = "2025-04-23"
        last_modified = "2025-05-27"
        threat_name = "Multi.Trojan.Goffloader"
        reference_sample = "c233aa4d7a672f08f6375f68e1f153d11e8e73df5adf72325a2e1a272f0428fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "praetorian-inc/goffloader/src/memory.ReadUIntFromPtr"
    condition:
        all of them
}

