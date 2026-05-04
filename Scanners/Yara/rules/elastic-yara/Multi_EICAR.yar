rule Multi_EICAR_ac8f42d6 {
    meta:
        author = "Elastic Security"
        id = "ac8f42d6-52da-46ec-8db1-5a5f69222a38"
        fingerprint = "bb0e0bdf70ec65d98f652e2428e3567013d5413f2725a2905b372fd18da8b9dd"
        creation_date = "2021-01-21"
        last_modified = "2022-01-13"
        threat_name = "Multi.EICAR.Not-a-virus"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
    condition:
        all of them
}

