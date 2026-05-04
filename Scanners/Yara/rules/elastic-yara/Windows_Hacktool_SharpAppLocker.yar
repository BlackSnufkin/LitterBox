rule Windows_Hacktool_SharpAppLocker_9645cf22 {
    meta:
        author = "Elastic Security"
        id = "9645cf22-f9b3-45ff-a5d8-513c59ad3d53"
        fingerprint = "720a96f7baa8af4e6189709ee906350c291e175ac861c83d425b235d9217bb32"
        creation_date = "2022-11-20"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.SharpAppLocker"
        reference_sample = "0f7390905abc132889f7b9a6d5b42701173aafbff5b8f8882397af35d8c10965"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" ascii wide nocase
        $print_str0 = "[+] Output written to:" ascii wide fullword
        $print_str1 = "[!] You can only select one Policy at the time." ascii wide fullword
        $print_str2 = "SharpAppLocker.exe --effective --allow --rules=\"FileHashRule,FilePathRule\" --outfile=\"C:\\Windows\\Tasks\\Rules.json\"" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

