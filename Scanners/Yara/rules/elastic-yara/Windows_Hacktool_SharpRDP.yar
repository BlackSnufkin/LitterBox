rule Windows_Hacktool_SharpRDP_80895fcb {
    meta:
        author = "Elastic Security"
        id = "80895fcb-b98e-4865-a1f6-87cbea327cea"
        fingerprint = "a7eb084004fce79efc39781044bad501a731163fa3ad6f9b8b334611d03f5379"
        creation_date = "2022-11-20"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.SharpRDP"
        reference_sample = "6e909861781a8812ee01bc59435fd73fd34da23fa9ad6d699eefbf9f84629876"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide nocase
        $print_str0 = "[+] Another user is logged on, asking to take over session" ascii wide fullword
        $print_str1 = "[+] Execution priv type   :  {0}" ascii wide fullword
        $print_str2 = "[+] Sleeping for 30 seconds" ascii wide fullword
        $print_str3 = "[X] Error: A password is required" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

