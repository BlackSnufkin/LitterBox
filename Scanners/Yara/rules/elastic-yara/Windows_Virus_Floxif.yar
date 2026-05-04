rule Windows_Virus_Floxif_493d1897 {
    meta:
        author = "Elastic Security"
        id = "493d1897-864e-4f18-8511-0c6c9d990990"
        fingerprint = "6a043d05ca24846cfba28b5ea603a3e512a5af4f4e15629851a922190245ca1e"
        creation_date = "2023-09-26"
        last_modified = "2023-11-02"
        threat_name = "Windows.Virus.Floxif"
        reference_sample = "e628b7973ee25fdfd8f849fdf5923c6fba48141de802b0b4ce3e9ad2e40fe470"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 54 24 04 80 7A 03 01 75 04 8D 42 04 C3 8D 42 04 53 8B C8 8A 5A 02 84 DB 74 02 30 19 8A 19 }
    condition:
        all of them
}

