rule Windows_Hacktool_SharpSCCM_9bef8dab {
    meta:
        author = "Elastic Security"
        id = "9bef8dab-af2e-46be-811a-0ac78d74a4ef"
        fingerprint = "dfbb7f142628eb7dc6c96dd271562d88a0970534af85464c10232ec01f58e35b"
        creation_date = "2024-03-25"
        last_modified = "2024-05-08"
        threat_name = "Windows.Hacktool.SharpSCCM"
        reference_sample = "2e169c4fd16627029445bb0365a2f9ee61ab6b3757b8ad02fd210ce85dc9c97f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $name = "SharpSCCM" wide fullword
        $s1 = "--relay-server" wide fullword
        $s2 = "--username" wide fullword
        $s3 = "--domain" wide fullword
        $s4 = "--sms-provider" wide fullword
        $s5 = "--wmi-namespace" wide fullword
        $s6 = "--management-point" wide fullword
        $s7 = "--get-system" wide fullword
        $s8 = "--run-as-user" wide fullword
        $s9 = "--register-client" wide fullword
        $s10 = "MS_Collection" wide fullword
        $s11 = "SOFTWARE\\Microsoft\\CCM" wide fullword
        $s12 = "CCM_POST" wide fullword
    condition:
        ($name and 2 of ($s*)) or 7 of ($s*)
}

