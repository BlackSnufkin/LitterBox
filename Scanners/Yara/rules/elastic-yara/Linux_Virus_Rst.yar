rule Linux_Virus_Rst_1214e2ae {
    meta:
        author = "Elastic Security"
        id = "1214e2ae-90e4-425e-b47f-0a0981623236"
        fingerprint = "a13a9825815a417be991db57f80dac4d0c541e303e4a4e6bd03c46ece73703ea"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Rst"
        reference_sample = "b0e4f44d2456960bb6b20cb468c4ca1390338b83774b7af783c3d03e49eebe44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 00 00 53 89 F3 CD 80 5B 58 5F 5E 5A 59 5B C3 }
    condition:
        all of them
}

