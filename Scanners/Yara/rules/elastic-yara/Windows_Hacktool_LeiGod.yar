rule Windows_Hacktool_LeiGod_89397ebf {
    meta:
        author = "Elastic Security"
        id = "89397ebf-2fdb-4607-85a1-b9c378b4e256"
        fingerprint = "04709d703cd0a062029a05baee160eb9579fe0503984f3059ce49e1bcfa6e963"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.LeiGod"
        reference_sample = "ae5cc99f3c61c86c7624b064fd188262e0160645c1676d231516bf4e716a22d3"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Device\\CtrlLeiGod" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_LeiGod_3f5c98c4 {
    meta:
        author = "Elastic Security"
        id = "3f5c98c4-03ba-4919-90b0-604d3cb9361e"
        fingerprint = "883dcad7097ad5713c4f45ce2fc232c3c1e61cf9dfdc81a194124d5995a64c9e"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.LeiGod"
        reference_sample = "0c42fe45ffa9a9c36c87a7f01510a077da6340ffd86bf8509f02c6939da133c5"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\LgDCatcher.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

