rule Linux_Trojan_Lala_51deb1f9 {
    meta:
        author = "Elastic Security"
        id = "51deb1f9-2d5f-4c41-99f3-138c15c35804"
        fingerprint = "220bcaa4f18b9474ddd3da921e1189d17330f0eb98fa55a193127413492fb604"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Lala"
        reference_sample = "f3af65d3307fbdc2e8ce6e1358d1413ebff5eeb5dbedc051394377a4dabffa82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D9 7C F3 89 D8 83 7D FC 00 7D 02 F7 D8 8B 55 08 }
    condition:
        all of them
}

