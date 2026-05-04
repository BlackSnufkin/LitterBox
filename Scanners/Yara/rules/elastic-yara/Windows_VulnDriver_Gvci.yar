rule Windows_VulnDriver_Gvci_f5a35359 {
    meta:
        author = "Elastic Security"
        id = "f5a35359-ee16-444a-aafd-c4ef162e46d4"
        fingerprint = "590e6b10c8bd1c299eb4ecd1368ac05d8811147c7ce3976de5e86d1a6d8bc14f"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Gvci"
        reference_sample = "42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\GVCIDrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

