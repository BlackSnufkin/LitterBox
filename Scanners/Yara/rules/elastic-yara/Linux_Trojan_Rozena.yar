rule Linux_Trojan_Rozena_56651c1d {
    meta:
        author = "Elastic Security"
        id = "56651c1d-548e-4a51-8f1c-e4add55ec14f"
        fingerprint = "a86abe550b5c698a244e1c0721cded8df17d2c9ed0ee764d6dea36acf62393de"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rozena"
        reference_sample = "997684fb438af3f5530b0066d2c9e0d066263ca9da269d6a7e160fa757a51e04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }
    condition:
        all of them
}

