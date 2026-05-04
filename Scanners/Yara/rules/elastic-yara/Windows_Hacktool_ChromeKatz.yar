rule Windows_Hacktool_ChromeKatz_fa232bba {
    meta:
        author = "Elastic Security"
        id = "fa232bba-07dd-45e0-9ca3-b1465eb9616d"
        fingerprint = "bf1da659e0de9c4e22851e77878066ae5f4aca75e61b35392887c12e125c91f8"
        creation_date = "2024-03-27"
        last_modified = "2024-05-08"
        threat_name = "Windows.Hacktool.ChromeKatz"
        reference_sample = "3f6922049422df14f1a1777001fea54b18fbfb0a4b03c4ee27786bfbc3b8ab87"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "CookieKatz.exe"
        $s2 = "Targeting Chrome"
        $s3 = "Targeting Msedgewebview2"
        $s4 = "Failed to find the first pattern"
        $s5 = "WalkCookieMap"
        $s6 = "Found CookieMonster on 0x%p"
        $s7 = "Cookie Key:"
        $s8 = "Failed to read cookie value" wide
        $s9 = "Failed to read cookie struct" wide
        $s10 = "Error reading left node"
    condition:
        5 of them
}

