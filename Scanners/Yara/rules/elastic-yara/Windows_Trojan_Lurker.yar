rule Windows_Trojan_Lurker_0ee51802 {
    meta:
        author = "Elastic Security"
        id = "0ee51802-4ff3-4edf-95ed-bb0338ff25d9"
        fingerprint = "c30bc4e25c1984268a3bb44c59081131d1e81254b94734f6af2b47969c0acd0e"
        creation_date = "2022-04-04"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.Lurker"
        reference_sample = "5718fd4f807e29e48a8b6a6f4484426ba96c61ec8630dc78677686e0c9ba2b87"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Device\\ZHWLurker0410" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

