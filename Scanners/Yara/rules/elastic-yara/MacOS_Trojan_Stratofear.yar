rule MacOS_Trojan_Stratofear_16d5648d {
    meta:
        author = "Elastic Security"
        id = "16d5648d-b7f4-4751-937f-fa0fc4b64479"
        fingerprint = "76a5054bef41ed8d698935a935a687c63165218fff11e631ac88752ee443c5ac"
        creation_date = "2024-12-13"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.Stratofear"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_0 = "monitor for when new device is mounted"
        $str_1 = "monitor for when it is waked up after %d minutes"
        $str_2 = "monitor for when size of file(%s) is changed"
        $str_3 = "embed://"
        $bin_0 = { 0F 10 05 B8 BE 2C 00 0F 11 45 CD 0F 28 05 A0 BE 2C 00 0F 29 45 C0 0F 28 05 85 BE 2C 00 0F 29 45 B0 0F 28 05 6A BE 2C 00 0F 29 45 A0 0F 28 05 4F BE 2C 00 0F 29 45 90 }
        $bin_1 = { 0F 28 4D A0 0F 28 55 B0 0F 28 5D C0 0F 11 58 34 0F 11 50 24 0F 11 48 14 0F 11 40 04 80 7D D0 0A }
    condition:
        3 of ($str_*) or 1 of ($bin_*)
}

