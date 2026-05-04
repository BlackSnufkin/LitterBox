rule Windows_Trojan_NanoRemote_7974c813 {
    meta:
        author = "Elastic Security"
        id = "7974c813-7e3c-45dd-84ff-955d340bf4d3"
        fingerprint = "57b605ef406dbc25444210679db74b6111570c4d66375f76f3806cae76881e94"
        creation_date = "2025-11-17"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.NanoRemote"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "/drive/v3/files/%s?alt=media" ascii fullword
        $str2 = "08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X" ascii fullword
        $str3 = "NanoRemote/" wide
        $str4 = "[+] pwd output:" wide
        $str5 = "Download task %s failed: write error (wrote %llu/%zu bytes)"
        $seq1 = { 48 83 7C 24 28 00 74 ?? 4C 8D 4C 24 20 41 B8 40 00 00 00 BA 00 00 01 00 48 8B 4C 24 28 FF 15 ?? ?? ?? ?? 85 C0 }
        $seq2 = { BF 06 00 00 00 89 78 48 8B 0D ?? ?? ?? ?? 89 48 ?? FF D3 89 78 78 8B 0D ?? ?? ?? ?? 89 48 7C FF D3 89 78 18 8B 0D }
    condition:
        4 of them
}

