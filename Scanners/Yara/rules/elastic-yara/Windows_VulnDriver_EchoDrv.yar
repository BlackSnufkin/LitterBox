rule Windows_VulnDriver_EchoDrv_d17ff31c {
    meta:
        author = "Elastic Security"
        id = "d17ff31c-59d1-4bea-be25-c6f7fe2b8c7b"
        fingerprint = "dcf828c8db88580faeaa78f4bcda5a01ff4e710cb3e1e0912a99665831a070b4"
        creation_date = "2023-10-31"
        last_modified = "2023-11-03"
        threat_name = "Windows.VulnDriver.EchoDrv"
        reference_sample = "ea3c5569405ed02ec24298534a983bcb5de113c18bc3fd01a4dd0b5839cd17b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "D:\\WACATACC\\Projects\\Programs\\Echo\\x64\\Release\\echo-driver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1
}

