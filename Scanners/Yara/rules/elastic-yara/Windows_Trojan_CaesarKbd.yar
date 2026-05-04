rule Windows_Trojan_CaesarKbd_32bb198b {
    meta:
        author = "Elastic Security"
        id = "32bb198b-ec03-4628-8e9b-bc36c2525ec7"
        fingerprint = "54ed92761bb619ae4dcec9c27127d6c2a74a575916249cd5db24b8deb2ee0588"
        creation_date = "2022-04-04"
        last_modified = "2022-06-09"
        threat_name = "Windows.Trojan.CaesarKbd"
        reference_sample = "d4335f4189240a3bcafa05fab01f0707cc8e3dd7a2998af734c24916d9e37ca8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "CaesarKbd_IOCtrl"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

