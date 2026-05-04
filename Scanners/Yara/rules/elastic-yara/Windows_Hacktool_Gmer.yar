rule Windows_Hacktool_Gmer_8aabdd5e {
    meta:
        author = "Elastic Security"
        id = "8aabdd5e-1ce7-4257-abaa-8d02dc6856a6"
        fingerprint = "960721d4d111a670907fe7d3ce01dfd134ad03a2d8440a945c75a7d46de46238"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.Gmer"
        reference_sample = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\gmer64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

