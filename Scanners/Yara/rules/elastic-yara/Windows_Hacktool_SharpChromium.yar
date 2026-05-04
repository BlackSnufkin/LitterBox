rule Windows_Hacktool_SharpChromium_41ce5080 {
    meta:
        author = "Elastic Security"
        id = "41ce5080-7d84-4a56-8de8-86959eb92057"
        fingerprint = "b6695ded1a6f647812c7f355e089a2ed7209ac59f51a97d8f6b1897bb1e7d9ad"
        creation_date = "2022-11-20"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.SharpChromium"
        reference_sample = "9dd65aa53728d51f0f3b9aaf51a24f8a2c3f84b4a4024245575975cf9ad7f2e5"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "F1653F20-D47D-4F29-8C55-3C835542AF5F" ascii wide nocase
        $print_str0 = "[X] Exception occurred while writing cookies to file: {0}" ascii wide fullword
        $print_str1 = "[*] All cookies written to {0}" ascii wide fullword
        $print_str2 = "\\{0}-cookies.json" ascii wide fullword
        $print_str3 = "[*] {0} {1} extraction." ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

