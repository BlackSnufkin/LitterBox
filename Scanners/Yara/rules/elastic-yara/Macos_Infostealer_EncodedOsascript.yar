rule Macos_Infostealer_EncodedOsascript_eeb54a7e {
    meta:
        author = "Elastic Security"
        id = "eeb54a7e-ebb3-4bf9-8538-2dbad9e514b9"
        fingerprint = "7b9d3cc64f3cfbdf1f9938ab923ff06eb6aef78fce633af891f5dd6a6b38dd2d"
        creation_date = "2024-08-19"
        last_modified = "2024-08-26"
        threat_name = "Macos.Infostealer.EncodedOsascript"
        reference_sample = "c1693ee747e31541919f84dfa89e36ca5b74074044b181656d95d7f40af34a05"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $xor_encoded_osascript = "osascript" xor(64)
        $base32_encoded_osascript = { 4E 35 5A 57 43 34 33 44 4F 4A 55 58 41 35 }
        $hex_encoded_osascript = "6f7361736372697074" ascii wide nocase
    condition:
        any of them
}

