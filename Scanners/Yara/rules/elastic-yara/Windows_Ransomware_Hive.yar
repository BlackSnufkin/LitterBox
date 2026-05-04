rule Windows_Ransomware_Hive_55619cd0 {
    meta:
        author = "Elastic Security"
        id = "55619cd0-6013-45e2-b15e-0dceff9571ab"
        fingerprint = "04df3169c50fbab4e2b495de5500c62ddf5e76aa8b4a7fc8435f39526f69c52b"
        creation_date = "2021-08-26"
        last_modified = "2022-01-13"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "google.com/encryptor.(*App).KillProcesses" ascii fullword
        $a2 = "- Do not shutdown or reboot your computers, unmount external storages." ascii fullword
        $a3 = "hive"
    condition:
        all of them
}

rule Windows_Ransomware_Hive_3ed67fe6 {
    meta:
        author = "Elastic Security"
        id = "3ed67fe6-6347-4aef-898d-4cb267bcbfc7"
        fingerprint = "a15acde0841f08fc44fdc1fea01c140e9e8af6275a65bec4a7b762494c9e6185"
        creation_date = "2021-08-26"
        last_modified = "2022-01-13"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bmr|sql|oracle|postgres|redis|vss|backup|sstp"
        $a2 = "key.hive"
        $a3 = "Killing processes"
        $a4 = "Stopping services"
        $a5 = "Removing itself"
    condition:
        all of them
}

rule Windows_Ransomware_Hive_b97ec33b {
    meta:
        author = "Elastic Security"
        id = "b97ec33b-d4cf-4b70-8ce8-8a5d20448643"
        fingerprint = "7f2c2d299942390d953599b180ed191d9db999275545a7ba29059fd49b858087"
        creation_date = "2021-08-26"
        last_modified = "2022-01-13"
        threat_name = "Windows.Ransomware.Hive"
        reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 74 C3 8B 44 24 78 8B 08 8B 50 04 8B 40 08 89 0C 24 89 54 24 04 89 44 }
    condition:
        all of them
}

