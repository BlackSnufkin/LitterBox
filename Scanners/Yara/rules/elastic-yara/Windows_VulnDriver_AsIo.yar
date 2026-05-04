rule Windows_VulnDriver_AsIo_5f9f29be {
    meta:
        author = "Elastic Security"
        id = "5f9f29be-9dbb-4d0f-84f5-7027c1413c2c"
        fingerprint = "82967badefb37a3964de583cb65f423afe46abc299d361c7a9cd407b146fd897"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.AsIo"
        reference_sample = "52a90fd1546c068b92add52c29fbb8a87d472a57e609146bbcb34862f9dcec15"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\AsIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

