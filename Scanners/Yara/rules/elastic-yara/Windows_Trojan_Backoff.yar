rule Windows_Trojan_Backoff_22798f00 {
    meta:
        author = "Elastic Security"
        id = "22798f00-ff2a-4f5f-a9ef-fab6d04ca679"
        fingerprint = "a45fc701844e6e0cfba5d8ef90d00960b5817af66e6b3d889a54d33539cd5d41"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Backoff"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\nsskrnl" fullword
        $str2 = "Upload KeyLogs" fullword
        $str3 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s" fullword
        $str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $str5 = "\\OracleJava\\Log.txt" fullword
        $str6 = "[Ctrl+%c]" fullword
    condition:
        3 of them
}

