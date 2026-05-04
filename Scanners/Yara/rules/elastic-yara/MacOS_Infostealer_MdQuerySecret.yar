rule MacOS_Infostealer_MdQuerySecret_5535ab96 {
    meta:
        author = "Elastic Security"
        id = "5535ab96-36aa-42ed-ab85-d8fd7fa6a368"
        fingerprint = "4fdad65ffdce106e837bbec747e63269f782a9b1ab2cfa9d2db204d252960ab4"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQuerySecret"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}secret/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}secret\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

