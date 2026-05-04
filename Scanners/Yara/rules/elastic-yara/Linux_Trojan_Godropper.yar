rule Linux_Trojan_Godropper_bae099bd {
    meta:
        author = "Elastic Security"
        id = "bae099bd-c19a-4893-96e8-63132dabce39"
        fingerprint = "5a7b0906ebc47130aefa868643e1e0a40508fe7a25bc55e5c41ff284ca2751e5"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Godropper"
        reference_sample = "704643f3fd11cda1d52260285bf2a03bccafe59cfba4466427646c1baf93881e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF FF 88 DB A2 31 03 A3 5A 5C 9A 19 0E DB }
    condition:
        all of them
}

