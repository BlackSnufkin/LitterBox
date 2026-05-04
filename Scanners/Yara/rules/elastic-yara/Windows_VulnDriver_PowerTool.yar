rule Windows_VulnDriver_PowerTool_044a8645 {
    meta:
        author = "Elastic Security"
        id = "044a8645-cc90-4ab2-8519-e207583de60d"
        fingerprint = "f79831f531f20cc1daeb86b860dffa02dd5a9d25c41cc1eff9f04eddbbd37864"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: kEvP64.sys"
        threat_name = "Windows.VulnDriver.PowerTool"
        reference_sample = "1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6B 00 45 00 76 00 50 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

