rule Linux_Trojan_Backconnect_c6803b39 {
    meta:
        author = "Elastic Security"
        id = "c6803b39-e2e0-4ab8-9ead-e53eab26bb53"
        fingerprint = "1dfb097c90b0cf008dc9d3ae624e08504755222f68ee23ed98d0fa8803cff91a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Backconnect"
        reference_sample = "a5e6b084cdabe9a4557b5ff8b2313db6c3bb4ba424d107474024030115eeaa0f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 78 3A 48 98 48 01 C3 49 01 C5 48 83 FB 33 76 DC 31 C9 BA 10 00 }
    condition:
        all of them
}

