rule Linux_Trojan_Xpmmap_7dcc3534 {
    meta:
        author = "Elastic Security"
        id = "7dcc3534-e94c-4c92-ac9b-a82b00fb045b"
        fingerprint = "397618543390fb8fd8b198f63034fe88b640408d75b769fb337433138dafcf66"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xpmmap"
        reference_sample = "765546a981921187a4a2bed9904fbc2ccb2a5876e0d45c72e79f04a517c1bda3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 89 45 F8 48 83 7D F8 FF 75 14 BF 10 0C 40 00 }
    condition:
        all of them
}

