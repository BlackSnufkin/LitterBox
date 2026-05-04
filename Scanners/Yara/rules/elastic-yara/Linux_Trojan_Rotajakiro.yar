rule Linux_Trojan_Rotajakiro_fb24f399 {
    meta:
        author = "Elastic Security"
        id = "fb24f399-d2bc-4cca-a3b8-4d924f11c83e"
        fingerprint = "6b19a49c93a0d3eb380c78ca21ce4f4d2991c35e68d2b75e173dc25118ba2c20"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rotajakiro"
        reference = "023a7f9ed082d9dd7be6eba5942bfa77f8e618c2d15a8bc384d85223c5b91a0c"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 56 41 55 41 54 49 89 FD 55 53 48 63 DE 48 83 EC 08 0F B6 17 80 }
    condition:
        all of them
}

