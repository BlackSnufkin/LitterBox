rule Linux_Hacktool_Infectionmonkey_6c84537b {
    meta:
        author = "Elastic Security"
        id = "6c84537b-6aa1-40d5-b14c-f78d7e67823d"
        fingerprint = "e9275f5fd8df389a4c99f69c09df1e3e515d8b958616e6d4d2c82d693deb4908"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Hacktool.Infectionmonkey"
        reference_sample = "d941943046db48cf0eb7f11e144a79749848ae6b50014833c5390936e829f6c3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 75 14 8B 54 24 0C 83 FA FF 0F 44 D0 83 C4 1C 89 D0 C3 8D 74 }
    condition:
        all of them
}

