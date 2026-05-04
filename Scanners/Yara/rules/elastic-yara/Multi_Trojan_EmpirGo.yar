rule Multi_Trojan_EmpirGo_38a23b2c {
    meta:
        author = "Elastic Security"
        id = "38a23b2c-574b-40a4-9cc7-b25e64ca83fa"
        fingerprint = "856d1a8ac1c5d117656a1ad1f47cba379fa1612252d6e3900fed8103474db8a3"
        creation_date = "2025-04-23"
        last_modified = "2025-05-27"
        threat_name = "Multi.Trojan.EmpirGo"
        reference_sample = "c233aa4d7a672f08f6375f68e1f153d11e8e73df5adf72325a2e1a272f0428fc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "EmpirGo/agent.(*MainAgent)."
        $b1 = "MissedCheckins"
        $b2 = "ReadDataDirBaseRels"
        $b3 = "getRandomSleepTime"
    condition:
        $a1 or all of ($b*)
}

