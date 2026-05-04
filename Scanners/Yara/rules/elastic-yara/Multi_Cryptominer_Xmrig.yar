rule Multi_Cryptominer_Xmrig_f9516741 {
    meta:
        author = "Elastic Security"
        id = "f9516741-aac1-4c67-ad63-3d222814864e"
        fingerprint = "14eef95b5a008e644c2fe2d600c1a883d018c1ab085f4496a3e2211329362d31"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        threat_name = "Multi.Cryptominer.Xmrig"
        reference_sample = "104f839b5da7bd77804ca5ec252d78dccb52800a2ef4fd1179db6deb764af42f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_1 = "no valid configuration found, try https://xmrig.com/wizard"
        $str_2 = "xmrig-"
        $str_3 = "XMRig "
        $str_4 = "--donate-level=N"
        $str_5 = "--coin=COIN"
        $str_6 = "--algo=ALGO"
        $str_7 = "hwloc topology successfully exported to \"%s\"\n"
    condition:
        6 of them
}

