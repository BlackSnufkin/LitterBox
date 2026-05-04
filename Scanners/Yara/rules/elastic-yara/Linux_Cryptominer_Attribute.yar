rule Linux_Cryptominer_Attribute_3683d149 {
    meta:
        author = "Elastic Security"
        id = "3683d149-fa9c-4dbb-85b9-8ce2b1d1d128"
        fingerprint = "31f45578eab3c94cff52056a723773d41aaad46d529b1a2063a0610d5948a633"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Attribute"
        reference_sample = "ec9e74d52d745275718fe272bfd755335739ad5f680f73f5a4e66df6eb141a63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 6F 20 66 61 73 74 29 20 6F 72 20 39 20 28 61 75 74 6F }
    condition:
        all of them
}

