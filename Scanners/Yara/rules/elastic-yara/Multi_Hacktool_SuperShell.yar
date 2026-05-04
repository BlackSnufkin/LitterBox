rule Multi_Hacktool_SuperShell_f7486598 {
    meta:
        author = "Elastic Security"
        id = "f7486598-0b60-4b40-932e-6abfba279b76"
        fingerprint = "116f89157bfe0d80ddcb8f55984169fa611a51a3d562ef719b13ef2ddd50c432"
        creation_date = "2024-09-12"
        last_modified = "2024-09-30"
        threat_name = "Multi.Hacktool.SuperShell"
        reference_sample = "18556a794f5d47f93d375e257fa94b9fb1088f3021cf79cc955eb4c1813a95da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "NHAS/reverse_ssh/internal/terminal"
        $b1 = "foreground|fingerprint|proxy|process_name"
        $b2 = "Failed to kill shell"
        $b3 = "Missing listening address"
    condition:
        $a and 1 of ($b*)
}

