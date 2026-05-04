rule Windows_Hacktool_EDRWFP_f6d7db7a {
    meta:
        author = "Elastic Security"
        id = "f6d7db7a-c55e-41dc-859b-6431464e72f4"
        fingerprint = "11e4224f53ddb5ef18aef5efeaa7ec6ec00072e57db5189e29a04feae6b3da31"
        creation_date = "2024-06-10"
        last_modified = "2024-07-02"
        threat_name = "Windows.Hacktool.EDRWFP"
        reference_sample = "a1fc2f3ded852f75e36e70ae39087e21ae5b6af10e2038d04e61bd500ba511e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "elastic-endpoint.exe"
        $s2 = "elastic-agent.exe"
        $s3 = "MsMpEng.exe"
        $s4 = "FwpmFilterAdd0"
    condition:
        all of them
}

