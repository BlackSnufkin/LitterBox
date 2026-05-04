rule Linux_Trojan_Connectback_bf194c93 {
    meta:
        author = "Elastic Security"
        id = "bf194c93-92d8-4eba-99c4-326a5ea76d0d"
        fingerprint = "6e72b14be0a0a6e42813fa82ee77d057246ccba4774897b38acf2dc30c894023"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Connectback"
        reference_sample = "6784cb86460bddf1226f71f5f5361463cbda487f813d19cd88e8a4a1eb1a417b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B6 0C B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }
    condition:
        all of them
}

