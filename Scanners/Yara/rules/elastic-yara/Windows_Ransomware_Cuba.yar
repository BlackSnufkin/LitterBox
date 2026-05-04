rule Windows_Ransomware_Cuba_e64a16b1 {
    meta:
        author = "Elastic Security"
        id = "e64a16b1-262c-4835-bd95-4dde89dd75f4"
        fingerprint = "840f2ebe2664db9a0918acf7d408ca8060ee0d3c330ad08b36e5be7f7e2cf069"
        creation_date = "2021-08-04"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Cuba"
        reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
        reference_sample = "33352a38454cfc247bc7465bf177f5f97d7fd0bd220103d4422c8ec45b4d3d0e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 45 EC 8B F9 8B 45 14 89 45 F0 8D 45 E4 50 8D 45 F8 66 0F 13 }
        $HeaderCheck = { 8B 06 81 38 46 49 44 45 75 ?? 81 78 04 4C 2E 43 41 74 }
    condition:
        any of them
}

rule Windows_Ransomware_Cuba_95a98e69 {
    meta:
        author = "Elastic Security"
        id = "95a98e69-ce6c-40c6-a05b-2366c663ad6e"
        fingerprint = "05cfd7803692149a55d9ced84828422b66e8b301c8c2aae9ca33c6b68e29bcf8"
        creation_date = "2021-08-04"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Cuba"
        reference = "https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis"
        reference_sample = "00f18713f860dc8394fb23a1a2b6280d1eb2f20a487c175433a7b495a1ba408d"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii fullword
        $a2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
        $a3 = ".cuba" wide fullword
    condition:
        all of them
}

