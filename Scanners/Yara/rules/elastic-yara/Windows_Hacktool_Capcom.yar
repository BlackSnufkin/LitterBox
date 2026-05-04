rule Windows_Hacktool_Capcom_7abae448 {
    meta:
        author = "Elastic Security"
        id = "7abae448-0ebc-433f-b368-0b8560da7197"
        fingerprint = "965e85fc3b2a21aef84c7c2bd59708b121d9635ce6bab177014b28fb00102884"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: CAPCOM Co.,Ltd."
        threat_name = "Windows.Hacktool.Capcom"
        reference_sample = "da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 41 50 43 4F 4D 20 43 6F 2E 2C 4C 74 64 2E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

