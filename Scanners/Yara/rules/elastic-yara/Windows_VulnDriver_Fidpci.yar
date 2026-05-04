rule Windows_VulnDriver_Fidpci_cb7f69b5 {
    meta:
        author = "Elastic Security"
        id = "cb7f69b5-5421-493b-adf7-75130d19b001"
        fingerprint = "19da3f67e302d0a70d40533553a19ba91a99a83609c01c8f296834a93fa325e2"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Fidpci"
        reference_sample = "3ac5e01689a3d745e60925bc7faca8d4306ae693e803b5e19c94906dc30add46"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\fidpcidrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

