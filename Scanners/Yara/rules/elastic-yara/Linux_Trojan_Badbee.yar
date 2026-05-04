rule Linux_Trojan_Badbee_231cb054 {
    meta:
        author = "Elastic Security"
        id = "231cb054-36a9-434f-8254-17fee38e5275"
        fingerprint = "ebe789fc467daf9276f72210f94e87b7fa79fc92a72740de49e47b71f123ed5c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Badbee"
        reference_sample = "832ba859c3030e58b94398ff663ddfe27078946a83dcfc81a5ef88351d41f4e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8D B4 41 31 44 97 10 83 F9 10 75 E4 89 DE C1 FE 14 F7 C6 01 00 }
    condition:
        all of them
}

