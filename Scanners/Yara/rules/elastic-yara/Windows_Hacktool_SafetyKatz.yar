rule Windows_Hacktool_SafetyKatz_072b7370 {
    meta:
        author = "Elastic Security"
        id = "072b7370-517b-45dc-af23-ba3adbd32fbd"
        fingerprint = "f0d11341fc91d2c45c07c6079aad24a11da03320286216be0a68461b6bf55b02"
        creation_date = "2022-11-20"
        last_modified = "2023-01-11"
        threat_name = "Windows.Hacktool.SafetyKatz"
        reference_sample = "89a456943cf6d2b3cd9cdc44f13a23640575435ed49fa754f7ed358c1a3b6ba9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide nocase
        $print_str0 = "[X] Not in high integrity, unable to grab a handle to lsass!" ascii wide fullword
        $print_str1 = "[X] Dump directory \"{0}\" doesn't exist!" ascii wide fullword
        $print_str2 = "[X] Process is not 64-bit, this version of Mimikatz won't work yo'!" ascii wide fullword
        $print_str3 = "[+] Dump successful!" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

