rule Windows_Trojan_Xpertrat_ce03c41d {
    meta:
        author = "Elastic Security"
        id = "ce03c41d-d5c3-43f5-b3ca-f244f177d710"
        fingerprint = "8aa4336ba6909c820f1164c78453629959e28cb619fda45dbe46291f9fbcbec4"
        creation_date = "2021-08-06"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Xpertrat"
        reference_sample = "d7f2fddb43eb63f9246f0a4535dfcca6da2817592455d7eceaacde666cf1aaae"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[XpertRAT-Mutex]" wide fullword
        $a2 = "XPERTPLUGIN" wide fullword
        $a3 = "keylog.tmp" wide fullword
    condition:
        all of them
}

