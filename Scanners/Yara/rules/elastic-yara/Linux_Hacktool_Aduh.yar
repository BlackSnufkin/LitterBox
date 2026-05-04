rule Linux_Hacktool_Aduh_6cae7c78 {
    meta:
        author = "Elastic Security"
        id = "6cae7c78-a4b4-4096-9f7c-746b1e5a1e38"
        fingerprint = "8d7b0c1a95ec15c7d1ede5670ccd448b166467ed8eb2b4f38ebbb2c8bc323cdc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Aduh"
        reference_sample = "9c67207546ad274dc78a0819444d1c8805537f9ac36d3c53eba9278ed44b360c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E3 51 89 E2 51 89 E1 B0 0B CD 80 31 C0 B0 01 CD }
    condition:
        all of them
}

