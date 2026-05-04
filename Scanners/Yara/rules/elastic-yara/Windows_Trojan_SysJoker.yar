rule Windows_Trojan_SysJoker_1ef19a12 {
    meta:
        author = "Elastic Security"
        id = "1ef19a12-ee26-47da-8d65-272f6749b476"
        fingerprint = "9123af8b8b27ebfb9199e70eb34d43378b1796319186d5d848d650a8be02d5d5"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.SysJoker"
        reference_sample = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" ascii fullword
        $a2 = "powershell.exe Expand-Archive -LiteralPath '" ascii fullword
        $a3 = "powershell.exe Invoke-WebRequest -Uri '" ascii fullword
        $a4 = "\\recoveryWindows.zip" ascii fullword
    condition:
        3 of them
}

rule Windows_Trojan_SysJoker_34559bcd {
    meta:
        author = "Elastic Security"
        id = "34559bcd-661a-4213-b896-2d7f882a16ef"
        fingerprint = "b1e01d0b94a60f6f5632a14d3d32f78bbe3049886ea3a3e838a29fb790a45918"
        creation_date = "2022-02-21"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.SysJoker"
        reference_sample = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\txc1.txt\" && type \"" ascii fullword
        $a2 = "tempo1.txt" nocase
        $a3 = "user_token="
        $a4 = "{\"status\":\"success\",\"result\":\"" ascii fullword
        $a5 = "\",\"av\":\"" ascii fullword
        $a6 = "aSwpEHc0QyIxPRAqNmkeEwskMW8HODkkYRkCICIrJysHNmtlIzQiChMiGAxzQg==" ascii fullword
        $a7 = "ESQuBT8uQyglJy4QOicGXDMiayYtPQ==" ascii fullword
    condition:
        4 of them
}

