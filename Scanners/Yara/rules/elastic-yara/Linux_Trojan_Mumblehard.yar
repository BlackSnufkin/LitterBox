rule Linux_Trojan_Mumblehard_523450aa {
    meta:
        author = "Elastic Security"
        id = "523450aa-6bb4-4863-9656-81a6e6cb7d88"
        fingerprint = "783f07e4f4625c061309af2d89e9ece0ba4a8ce21a7d93ce19cd32bcd6ad38e9"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Mumblehard"
        reference_sample = "a637ea8f070e1edf2c9c81450e83934c177696171b24b4dff32dfb23cefa56d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 09 75 05 89 03 89 53 04 B8 02 00 00 00 50 80 F9 09 75 0B CD 80 }
    condition:
        all of them
}

