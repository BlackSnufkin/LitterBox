rule Windows_Wiper_DoubleZero_65ec0c50 {
    meta:
        author = "Elastic Security"
        id = "65ec0c50-4038-46a7-879b-fbb4aab18725"
        fingerprint = "2441bcdf7bc48df098f4ef68231fb15fc5c8f96af2e170de77f1718487b945b2"
        creation_date = "2022-03-22"
        last_modified = "2022-04-12"
        threat_name = "Windows.Wiper.DoubleZero"
        reference_sample = "3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105355fe"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "\\Users\\\\.*?\\\\AppData\\\\Roaming\\\\Microsoft.*" wide fullword
        $s2 = "\\Users\\\\.*?\\\\AppData\\\\Local\\\\Application Data.*" wide fullword
        $s3 = "\\Users\\\\.*?\\\\Local Settings.*" wide fullword
        $s4 = "get__beba00adeeb086e6" ascii fullword
        $s5 = "FileShareWrite" ascii fullword
    condition:
        all of them
}

