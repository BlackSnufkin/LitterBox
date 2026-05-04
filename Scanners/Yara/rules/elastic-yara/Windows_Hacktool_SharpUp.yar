rule Windows_Hacktool_SharpUp_e5c87c9a {
    meta:
        author = "Elastic Security"
        id = "e5c87c9a-6b4d-49af-85d1-6bb60123c057"
        fingerprint = "4c6e70b7ce3eb3fc05966af6c3847f4b7282059e05c089c20f39f226efb9bf87"
        creation_date = "2022-10-20"
        last_modified = "2022-11-24"
        threat_name = "Windows.Hacktool.SharpUp"
        reference_sample = "45e92b991b3633b446473115f97366d9f35acd446d00cd4a05981a056660ad27"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" ascii wide nocase
        $str0 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.bat|\\.ps1|\\.vbs))\\W*" ascii wide
        $str1 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
        $str2 = "SELECT * FROM win32_service WHERE Name LIKE '{0}'" ascii wide
        $print_str1 = "[!] Modifialbe scheduled tasks were not evaluated due to permissions." ascii wide
        $print_str2 = "[+] Potenatially Hijackable DLL: {0}" ascii wide
        $print_str3 = "Registry AutoLogon Found" ascii wide
    condition:
        $guid or (all of ($str*) and 1 of ($print_str*))
}

