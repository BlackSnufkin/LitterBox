rule Windows_Trojan_Garble_eae7f2f7 {
    meta:
        author = "Elastic Security"
        id = "eae7f2f7-49b3-427c-9cf3-cce64d772c78"
        fingerprint = "b72b8d475ef50a5e703d741f195d8ce0916f46ee5744c5bc7c8d452ab23df388"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Garble"
        reference_sample = "4820a1ec99981e03675a86c4c01acba6838f04945b5f753770b3de4e253e1b8c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = ".\"G!-$G#-&J%.(G'-*G)-,J+..G--0G/-2J1.4G3-6G5-8J7.:G9-<G;->J=+@A?-BAA*DAC*FAE*HFG+JAI-LAK*NAM*PAO*RFQ+TAS-VAU9"
    condition:
        all of them
}

