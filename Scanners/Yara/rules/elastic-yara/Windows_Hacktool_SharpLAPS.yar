rule Windows_Hacktool_SharpLAPS_381c3f40 {
    meta:
        author = "Elastic Security"
        id = "381c3f40-b6c6-4e50-be28-3d34ba07b644"
        fingerprint = "556b9ba9c0a2f08ff0b27e38e273f5817011de335436feb2a30cac74285d7e4f"
        creation_date = "2022-12-22"
        last_modified = "2022-12-22"
        threat_name = "Windows.Hacktool.SharpLAPS"
        reference_sample = "ef0d508b3051fe6f99ba55202a17237f29fdbc0085e3f5c99b1aef52c8ebe425"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "1e0986b4-4bf3-4cea-a885-347b6d232d46" ascii wide nocase
        $str_name = "SharpLAPS.exe" ascii wide
        $str0 = "Using the current session" ascii wide
        $str1 = "Extracting LAPS password" ascii wide
        $str2 = "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=" ascii wide
        $str4 = "Machine" ascii wide
        $str5 = "sAMAccountName" ascii wide
        $str6 = "ms-Mcs-AdmPwd" ascii wide
    condition:
        $guid or 6 of ($str*)
}

