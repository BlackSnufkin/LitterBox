rule Windows_Trojan_PrivateLoader_96ac2734 {
    meta:
        author = "Elastic Security"
        id = "96ac2734-e36c-4ce2-bb40-b6bd77694333"
        fingerprint = "029056908abef6c3ceecf7956e64a6d25b67c391f699516b3202d2aa3733f15a"
        creation_date = "2023-01-03"
        last_modified = "2023-02-01"
        threat_name = "Windows.Trojan.PrivateLoader"
        reference_sample = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $xor_decrypt = { 0F 28 85 ?? ?? FF FF 66 0F EF ?? ?? FE FF FF 0F 29 85 ?? ?? FF FF 0F 28 85 ?? ?? FF FF }
        $str0 = "https://ipinfo.io/" wide
        $str1 = "Content-Type: application/x-www-form-urlencoded" wide
        $str2 = "https://db-ip.com/" wide
    condition:
        all of ($str*) and #xor_decrypt > 3
}

