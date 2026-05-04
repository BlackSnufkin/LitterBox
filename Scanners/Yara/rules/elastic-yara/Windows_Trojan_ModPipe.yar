rule Windows_Trojan_ModPipe_12bc2604 {
    meta:
        author = "Elastic Security"
        id = "12bc2604-d3fe-40d6-8a7c-5bd53e403453"
        fingerprint = "30ff9f28cec84496ae7c809ec0401bc10573c690d93f3fb3865b5a913508795e"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.ModPipe"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0)" fullword
        $a2 = "/robots.txt" fullword
        $a3 = "www.yahoo.com/?"
        $a4 = "www.google.com/?"
    condition:
        all of them
}

