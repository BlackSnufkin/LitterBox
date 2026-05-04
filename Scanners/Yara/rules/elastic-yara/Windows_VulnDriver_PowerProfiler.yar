rule Windows_VulnDriver_PowerProfiler_2eedff78 {
    meta:
        author = "Elastic Security"
        id = "2eedff78-aa9b-4dab-b5f4-187bd2fc9a0c"
        fingerprint = "1273f1cd2de84076be28d7fb5fdac5fc9ab0de6f4e18915bdce6333181983cfb"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: AMDPowerProfiler.sys, Version: 6.1.0.0"
        threat_name = "Windows.VulnDriver.PowerProfiler"
        reference_sample = "0af5ccb3d33a9ba92071c9637be6254030d61998733a5eb3583e865e17844e05"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 50 00 6F 00 77 00 65 00 72 00 50 00 72 00 6F 00 66 00 69 00 6C 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x05][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

