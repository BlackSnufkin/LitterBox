rule Windows_Ransomware_Royal_b7d42109 {
    meta:
        author = "Elastic Security"
        id = "b7d42109-f327-4ec3-86ac-d1ebb9478860"
        fingerprint = "ff518f25b39b02769b67c437f38958d14e4e8f50b91f4c73591203da297a5d2a"
        creation_date = "2022-11-04"
        last_modified = "2022-12-20"
        threat_name = "Windows.Ransomware.Royal"
        reference_sample = "491c2b32095174b9de2fd799732a6f84878c2e23b9bb560cd3155cbdc65e2b80"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Try Royal today and enter the new era of data security" ascii fullword
        $a2 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii fullword
        $a3 = "http://royal"
        $a4 = "\\README.TXT" wide fullword
    condition:
        all of them
}

