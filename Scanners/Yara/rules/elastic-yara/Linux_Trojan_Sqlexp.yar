rule Linux_Trojan_Sqlexp_1aa5001e {
    meta:
        author = "Elastic Security"
        id = "1aa5001e-0609-4830-9c6f-675985fa50cf"
        fingerprint = "afce33f5bf064afcbd8b1639755733c99171074457272bf08f0c948d67427808"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sqlexp"
        reference_sample = "714a520fc69c54bcd422e75f4c3b71ce636cfae7fcec3c5c413d1294747d2dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E3 52 53 89 E1 B0 0B CD 80 00 00 ?? 00 }
    condition:
        all of them
}

