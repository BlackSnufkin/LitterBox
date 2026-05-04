rule Linux_Trojan_Zpevdo_7f563544 {
    meta:
        author = "Elastic Security"
        id = "7f563544-4ef3-460f-9a36-23d086f9c421"
        fingerprint = "a2113b38c27ee7e22313bd0ffbcabadfbf7f3f33d241a97db2dc86299775afd6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Zpevdo"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 48 89 E5 48 83 EC 20 89 7D EC 48 89 75 E0 BE 01 00 00 00 BF 11 00 }
    condition:
        all of them
}

