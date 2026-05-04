rule Windows_Trojan_ProtectS_9f6eaa90 {
    meta:
        author = "Elastic Security"
        id = "9f6eaa90-b3d4-4f0f-a81e-8010be0a6d36"
        fingerprint = "46bf59901876794dcc338923076939d765d3ce7f14d784b9687fbc05461ed6b4"
        creation_date = "2022-04-04"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.ProtectS"
        reference_sample = "c0330e072b7003f55a3153ac3e0859369b9c3e22779b113284e95ce1e2ce2099"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\ProtectS.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

