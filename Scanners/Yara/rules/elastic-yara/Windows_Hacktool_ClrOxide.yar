rule Windows_Hacktool_ClrOxide_d92d9575 {
    meta:
        author = "Elastic Security"
        id = "d92d9575-9ad9-464f-95a3-8e100666d7fa"
        fingerprint = "b403acddadc5adb982a9ee0e0513ecd471b728680cc9a6cd8cd8150eb9c02776"
        creation_date = "2024-02-29"
        last_modified = "2024-03-21"
        threat_name = "Windows.Hacktool.ClrOxide"
        reference_sample = "f3a4900eff80563bff586ced172c3988347980f902aceef2f9f9f6d188fac8e3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "clroxide..primitives..imethodinfo"
        $s2 = "clroxide..clr..Clr"
        $s3 = "\\src\\primitives\\icorruntimehost.rs"
        $s4 = "\\src\\primitives\\iclrruntimeinfo.rs"
        $s5 = "\\src\\primitives\\iclrmetahost.rs"
        $s6 = "clroxide\\src\\clr\\mod.rs"
        $s7 = "__clrcall"
    condition:
        2 of them
}

