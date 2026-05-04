rule Windows_VulnDriver_Lha_f72bff9a {
    meta:
        author = "Elastic Security"
        id = "f72bff9a-046c-4e02-9e11-4787c8aada75"
        fingerprint = "3b464386a60747131012d8380a34bed9329b02ac5cdc7b69b951f4f681243f35"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: LHA.sys"
        threat_name = "Windows.VulnDriver.Lha"
        reference_sample = "e75714f8e0ff45605f6fc7689a1a89c7dcd34aab66c6131c63fefaca584539cf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 48 00 41 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

