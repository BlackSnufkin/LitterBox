rule Windows_Trojan_Cryptbot_489a6562 {
    meta:
        author = "Elastic Security"
        id = "489a6562-870c-4105-9bb7-52ab09e5b09c"
        fingerprint = "f4578d79f8923706784e9d55a70ec74051273a945d2b277daa6229724defec3f"
        creation_date = "2021-08-18"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Cryptbot"
        reference_sample = "423563995910af04cb2c4136bf50607fc26977dfa043a84433e8bd64b3315110"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c rd /s /q %Temp%\\" wide fullword
        $a2 = "\\_Files\\_AllPasswords_list.txt" wide fullword
        $a3 = "\\files_\\cryptocurrency\\log.txt" wide fullword
        $a4 = "%wS\\%wS\\%wS.tmp" wide fullword
        $a5 = "%AppData%\\waves-exchange" wide fullword
    condition:
        all of them
}

rule Windows_Trojan_Cryptbot_b5ba0d9f {
    meta:
        author = "Elastic Security"
        id = "b5ba0d9f-9a50-4202-9a7a-19dd1fc002db"
        fingerprint = "4f13083b597b3093ee7a0802e3fb5be82f95b526d03403bc0c8c29a07d3191d6"
        creation_date = "2025-02-14"
        last_modified = "2025-05-27"
        threat_name = "Windows.Trojan.Cryptbot"
        reference_sample = "ec0d356acab765845f3a575925bcf37bb123d9e31a7d715a40ab9a45c8ab9747"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "verifying oof" fullword
        $a2 = "Memory allocation failed for passw1." fullword
        $a3 = "curl_easy_perform() failed: %s" fullword
        $a4 = "vbox_first" fullword
        $a5 = "No 'filename=' found in the Content-Disposition header." fullword
        $a6 = "after json obj2" fullword
        $a7 = "password len %d and %d" fullword
        $a8 = "Attempting to download file (attempt %d)..." fullword
        $a9 = "Combined password: '%s'" fullword
        $a10 = "before run request" fullword
    condition:
        6 of them
}

