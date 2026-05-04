rule Linux_Ransomware_BlackSuit_9f53e7e5 {
    meta:
        author = "Elastic Security"
        id = "9f53e7e5-7177-4e17-ac12-9214c4deddf2"
        fingerprint = "34355cb1731fe6c8fa684a484943127f8fdf3814d45025e29bdf25a08b4890fd"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.BlackSuit"
        reference_sample = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "esxcli vm process list > list_" fullword
        $a2 = "Drop readme failed: %s(%d)" fullword
        $a3 = "README.BlackSuit.txt" fullword
    condition:
        2 of them
}

