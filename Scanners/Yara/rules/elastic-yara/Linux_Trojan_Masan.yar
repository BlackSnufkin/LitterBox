rule Linux_Trojan_Masan_5369c678 {
    meta:
        author = "Elastic Security"
        id = "5369c678-9a74-42fe-a4b3-b4d48126bb22"
        fingerprint = "5fd243bf05cafd7db33d6c0167f77148ae53983906e917e174978130ae08062a"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Masan"
        reference_sample = "f2de9f39ca3910d5b383c245d8ca3c1bdf98e2309553599e0283062e0aeff17f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 E4 83 7D E4 FF 75 ?? 68 ?? 90 04 08 }
    condition:
        all of them
}

