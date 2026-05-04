rule Windows_Trojan_Fickerstealer_cc02e75e {
    meta:
        author = "Elastic Security"
        id = "cc02e75e-2049-4ee4-9302-e491e7dad696"
        fingerprint = "022088764645d85dd20d1ce201395b4e79e3e716723715687eaecfcbe667615e"
        creation_date = "2021-07-22"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Fickerstealer"
        reference_sample = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
        severity = 80
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii fullword
        $a2 = "\"SomeNone" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Fickerstealer_f2159bec {
    meta:
        author = "Elastic Security"
        id = "f2159bec-a3ce-47a9-91ad-43b8a19ac172"
        fingerprint = "0671691c6d5c7177fe155e4076ab39bf5f909ed300f32c1530e80d471dff0296"
        creation_date = "2021-07-22"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Fickerstealer"
        reference_sample = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 10 12 F2 0F 10 5A 08 31 C1 89 C6 8B 42 50 89 7D F0 F2 0F 11 8D 18 FF }
    condition:
        all of them
}

