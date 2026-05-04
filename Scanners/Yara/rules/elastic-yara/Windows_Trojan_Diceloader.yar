rule Windows_Trojan_Diceloader_b32c6b99 {
    meta:
        author = "Elastic Security"
        id = "b32c6b99-f634-4c6f-98f4-39954ef15afa"
        fingerprint = "15d4bc57c03a560608ae69551aa46d1786072b3d78d747512f8ac3e6822a7b93"
        creation_date = "2021-04-23"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Diceloader"
        reference_sample = "a3b3f56a61c6dc8ba2aa25bdd9bd7dc2c5a4602c2670431c5cbc59a76e2b4c54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "D$0GET " ascii fullword
        $a2 = "D$THostf" ascii fullword
        $a3 = "D$,POST" ascii fullword
        $a4 = "namef" ascii fullword
        $a5 = "send" ascii fullword
        $a6 = "log.ini" wide
        $a7 = { 70 61 73 73 00 00 65 6D 61 69 6C 00 00 6C 6F 67 69 6E 00 00 73 69 67 6E 69 6E 00 00 61 63 63 6F 75 6E 74 00 00 70 65 72 73 69 73 74 65 6E 74 00 00 48 6F 73 74 3A 20 }
    condition:
        all of them
}

rule Windows_Trojan_Diceloader_15eeb7b9 {
    meta:
        author = "Elastic Security"
        id = "15eeb7b9-311f-477b-8ae1-b8f689a154b7"
        fingerprint = "4cc70bec5d241c6f84010fbfe2eafbc6ec6d753df2bb3f52d9498b54b11fc8cb"
        creation_date = "2021-04-23"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Diceloader"
        reference_sample = "a1202df600d11ad2c61050e7ba33701c22c2771b676f54edd1846ef418bea746"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { E9 92 9D FF FF C3 E8 }
        $a2 = { E9 E8 61 FF FF C3 E8 }
    condition:
        any of them
}

