rule Windows_VulnDriver_Speedfan_9b590eee {
    meta:
        author = "Elastic Security"
        id = "9b590eee-5938-4293-afac-c9e730753413"
        fingerprint = "c58a8c3bfa710896c35262cc880b9afbadcdfdd73d9969c707e7b5b64e6a70b5"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Sokno S.R.L."
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

