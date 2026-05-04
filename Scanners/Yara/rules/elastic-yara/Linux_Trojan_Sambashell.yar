rule Linux_Trojan_Sambashell_f423755d {
    meta:
        author = "Elastic Security"
        id = "f423755d-60ec-4442-beb1-0820df0fe00b"
        fingerprint = "ea13320c358cadc8187592de73ceb260a00f28907567002d4f093be21f111f74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sambashell"
        reference_sample = "bd8a3728a59afbf433799578ef597b9a7211c8d62e87a25209398814851a77ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 00 01 00 00 00 FC 0E 00 00 FC 1E 00 00 FC 1E 00 00 74 28 00 00 }
    condition:
        all of them
}

