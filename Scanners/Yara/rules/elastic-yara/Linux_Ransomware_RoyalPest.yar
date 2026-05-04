rule Linux_Ransomware_RoyalPest_502a3db6 {
    meta:
        author = "Elastic Security"
        id = "502a3db6-4711-42c7-8178-c3150f184fc6"
        fingerprint = "4bde7998f41ef3d0f2769078cf56e03d36eacf503f859a23fc442ced95d839cb"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.RoyalPest"
        reference_sample = "09a79e5e20fa4f5aae610c8ce3fe954029a91972b56c6576035ff7e0ec4c1d14"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hit by Royal ransomware."
        $a2 = "Please contact us via :"
        $a3 = ".onion/%s"
        $a4 = "esxcli vm process list > list"
    condition:
        3 of them
}

