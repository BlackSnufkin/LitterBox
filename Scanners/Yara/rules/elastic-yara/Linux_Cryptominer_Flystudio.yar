rule Linux_Cryptominer_Flystudio_579a3a4d {
    meta:
        author = "Elastic Security"
        id = "579a3a4d-ddb0-4f73-9224-16fba973d624"
        fingerprint = "148b27046f72a7645ebced9f76424ffd7b368347311b04c9357d5d4ea8d373fb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Flystudio"
        reference_sample = "84afc47554cf42e76ef8d28f2d29c28f3d35c2876cec2fb1581b0ac7cfe719dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EF C1 66 0F 72 F1 05 66 0F EF C2 66 0F EF C1 66 0F 6F CD 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Flystudio_0a370634 {
    meta:
        author = "Elastic Security"
        id = "0a370634-51de-46bf-9397-c41ef08a7b83"
        fingerprint = "6613ddd986e2bf4b306cd1a5c28952da8068f1bb533c53557e2e2add5c2dbd1f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Flystudio"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 D7 19 66 41 0F EF E9 66 0F EF EF 66 0F 6F FD 66 41 0F FE FD 66 44 0F }
    condition:
        all of them
}

