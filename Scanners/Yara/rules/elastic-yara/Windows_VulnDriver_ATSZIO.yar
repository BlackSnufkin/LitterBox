rule Windows_VulnDriver_ATSZIO_e22cc429 {
    meta:
        author = "Elastic Security"
        id = "e22cc429-0285-4ab1-ae35-7e905e467182"
        fingerprint = "21cf1d00acde85bdae8c4cf6d59b0d224458de30a32dbddebd99eab48e1126bb"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: ATSZIO.sys"
        threat_name = "Windows.VulnDriver.ATSZIO"
        reference_sample = "01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

