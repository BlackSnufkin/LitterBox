rule Linux_Cryptominer_Xpaj_fdbd614e {
    meta:
        author = "Elastic Security"
        id = "fdbd614e-e628-43ff-86d4-1057f9d544ac"
        fingerprint = "456b69d4035aa2d682ba081c2f7b24c696f655ec164645f83c9aef5bd262f510"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Xpaj"
        reference_sample = "3e2b1b36981713217301dd02db33fb01458b3ff47f28dfdc795d8d1d332f13ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 72 6F 72 3A 20 47 65 74 25 73 20 74 65 6D 70 20 72 65 74 75 }
    condition:
        all of them
}

