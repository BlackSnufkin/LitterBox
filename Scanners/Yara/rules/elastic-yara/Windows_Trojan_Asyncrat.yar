rule Windows_Trojan_Asyncrat_11a11ba1 {
    meta:
        author = "Elastic Security"
        id = "11a11ba1-c178-4415-9c09-45030b500f50"
        fingerprint = "715ede969076cd413cebdfcf0cdda44e3a6feb5343558f18e656f740883b41b8"
        creation_date = "2021-08-05"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Asyncrat"
        reference_sample = "fe09cd1d13b87c5e970d3cbc1ebc02b1523c0a939f961fc02c1395707af1c6d1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide fullword
        $a2 = "Stub.exe" wide fullword
        $a3 = "get_ActivatePong" ascii fullword
        $a4 = "vmware" wide fullword
        $a5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide fullword
        $a6 = "get_SslClient" ascii fullword
    condition:
        all of them
}

