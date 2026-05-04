rule Windows_Hacktool_PhysMem_cc0978df {
    meta:
        author = "Elastic Security"
        id = "cc0978df-153e-4421-8be8-37a0824133e2"
        fingerprint = "b94d5530dc3db4101b6ef06dc2421a10785f47bcb26d54f309a250a68699fa83"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: physmem.sys"
        threat_name = "Windows.Hacktool.PhysMem"
        reference_sample = "c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 73 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_Hacktool_PhysMem_b3fa382b {
    meta:
        author = "Elastic Security"
        id = "b3fa382b-48a5-4004-92ad-bba0d42243ad"
        fingerprint = "81285d1d8bdb575cb3ebf7f2df2555544e3f1342917e207def00c358a77cd620"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.PhysMem"
        reference_sample = "88df37ede18bea511f1782c1a6c4915690b29591cf2c1bf5f52201fbbb4fa2b9"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Phymemx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

