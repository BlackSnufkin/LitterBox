rule Linux_Cryptominer_Bscope_348b7fa0 {
    meta:
        author = "Elastic Security"
        id = "348b7fa0-e226-4350-8697-345ae39fa0f6"
        fingerprint = "caae9d3938f9269f8bc30e4837021513ca6e4e2edd1117d235b0d25474df5357"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Bscope"
        reference_sample = "a6fb80d77986e00a6b861585bd4e573a927e970fb0061bf5516f83400ad7c0db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 8B 00 03 45 C0 89 02 8B 45 08 8D 50 08 8B 45 08 83 C0 08 }
    condition:
        all of them
}

