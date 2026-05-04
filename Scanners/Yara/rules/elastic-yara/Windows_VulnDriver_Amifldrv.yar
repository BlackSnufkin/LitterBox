rule Windows_VulnDriver_Amifldrv_e387d5ad {
    meta:
        author = "Elastic Security"
        id = "e387d5ad-fde8-401b-bdcf-044c4f7f5fbd"
        fingerprint = "03f898088f37f3c9991fb70d7fb8548908cfac4e03bb2bfe88b11a65157909a8"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Amifldrv"
        reference_sample = "fda506e2aa85dc41a4cbc23d3ecc71ab34e06f1def736e58862dc449acbc2330"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\amifldrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

