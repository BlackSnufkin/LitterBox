rule Windows_PUP_Generic_198b73aa {
    meta:
        author = "Elastic Security"
        id = "198b73aa-d7dd-4f28-bf1c-02672a03d031"
        fingerprint = "23c11df4ce2ec2d30b1916b73fc94a84b6a817c1686905fd69fa7a6528798d5f"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Windows.PUP.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[%i.%i]av=[error]" fullword
        $a2 = "not_defined" fullword
        $a3 = "osver=%d.%d-ServicePack %d" fullword
    condition:
        all of them
}

