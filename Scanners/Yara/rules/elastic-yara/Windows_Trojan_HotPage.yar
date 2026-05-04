rule Windows_Trojan_HotPage_414f235f {
    meta:
        author = "Elastic Security"
        id = "414f235f-5e16-449a-9ac5-556655c4418e"
        fingerprint = "6f590056d3f7bb9f743861e8d317ec589d8703353428dfcea9a6d2f61f266cdf"
        creation_date = "2024-07-18"
        last_modified = "2024-07-26"
        threat_name = "Windows.Trojan.HotPage"
        reference_sample = "b8464126b64c809b4ab47aa91c5f322ce2c0ae4fd668a43de738a5caa7567225"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $SpcSpOpusInfo = { 30 48 A0 1A 80 18 6E 56 53 17 76 FE 7F 51 7F 51 7E DC 79 D1 62 80 67 09 96 50 51 6C 53 F8 }
        $s1 = "\\Device\\KNewTableBaseIo"
        $s2 = "Release\\DwAdsafeLoad.pdb"
        $s3 = "RedDriver.pdb"
        $s4 = "Release\\DwAdSafe.pdb"
        $s5 = "[%s] Begin injecting Broser pid=[%d]"
        $s6 = "[%s] ADDbrowser PID ->[%d]"
    condition:
        $SpcSpOpusInfo or 2 of ($s*)
}

