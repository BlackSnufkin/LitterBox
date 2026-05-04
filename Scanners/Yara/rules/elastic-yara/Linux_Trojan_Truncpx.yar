rule Linux_Trojan_Truncpx_894d60f8 {
    meta:
        author = "Elastic Security"
        id = "894d60f8-bea6-4b09-b8ab-526308575a01"
        fingerprint = "440ce5902642aeef56b6989df4462d01faadc479f1362c0ed90d1011e8737bc3"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Truncpx"
        reference_sample = "2f09f2884fd5d3f5193bfc392656005bce6b935c12b3049ac8eb96862e4645ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { B9 51 FE 88 63 A1 08 08 09 C5 1A FF D3 AB B2 28 }
    condition:
        all of them
}

