rule Linux_Cryptominer_Miancha_646803ef {
    meta:
        author = "Elastic Security"
        id = "646803ef-e8a5-46e2-94a5-dcc6cb41cead"
        fingerprint = "b22f87b60c19855c3ac622bc557655915441f5e12c7d7c27c51c05e12c743ee5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Miancha"
        reference_sample = "4c7761c9376ed065887dc6ce852491641419eb2d1f393c37ed0a5cb29bd108d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F DC 66 0F 73 FB 04 66 0F EF C1 66 0F 6F D3 66 0F EF C7 66 0F 6F }
    condition:
        all of them
}

