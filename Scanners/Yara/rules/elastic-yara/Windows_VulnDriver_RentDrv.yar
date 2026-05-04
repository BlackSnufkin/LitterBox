rule Windows_VulnDriver_RentDrv_b6711b6b {
    meta:
        author = "Elastic Security"
        id = "b6711b6b-50c6-4859-9098-454ac8c86708"
        fingerprint = "241bb2c74d62bb29f09982b87fda4df93d2975db67ebd7831d632fafc8d8a126"
        creation_date = "2024-08-19"
        last_modified = "2024-09-30"
        threat_name = "Windows.VulnDriver.RentDrv"
        reference_sample = "9165d4f3036919a96b86d24b64d75d692802c7513f2b3054b20be40c212240a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "rentdrv_x64.pdb"
        $str2 = "KillProcess"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and all of them
}

