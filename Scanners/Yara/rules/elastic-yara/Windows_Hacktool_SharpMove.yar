rule Windows_Hacktool_SharpMove_05e28928 {
    meta:
        author = "Elastic Security"
        id = "05e28928-6109-4afe-bd86-908d354ddd80"
        fingerprint = "634efb2dedbb181a31ea41ff34d1d0810d1ab4823c8611737d68cb56601a052d"
        creation_date = "2022-11-20"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.SharpMove"
        reference_sample = "051f60f9f4665b96f764810defe9525ae7b4f9898249b83a23094cee63fa0c3b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide nocase
        $print_str0 = "[X]  Failed to connecto to WMI: {0}" ascii wide fullword
        $print_str1 = "[+] Executing DCOM ShellBrowserWindow   : {0}" ascii wide fullword
        $print_str2 = "[+]  User credentials  : {0}" ascii wide fullword
        $print_str3 = "[+] Executing DCOM ExcelDDE   : {0}" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

