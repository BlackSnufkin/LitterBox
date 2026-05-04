rule Windows_Trojan_Azorult_38fce9ea {
    meta:
        author = "Elastic Security"
        id = "38fce9ea-a94e-49d3-8eef-96fe06ad27f8"
        fingerprint = "0655018fc803469c6d89193b75b4967fd02400fae07364ffcd11d1bc6cbbe74a"
        creation_date = "2021-08-05"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Azorult"
        reference_sample = "405d1e6196dc5be1f46a1bd07c655d1d4b36c32f965d9a1b6d4859d3f9b84491"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c %WINDIR%\\system32\\timeout.exe 3 & del \"" wide fullword
        $a2 = "%APPDATA%\\.purple\\accounts.xml" wide fullword
        $a3 = "%TEMP%\\curbuf.dat" wide fullword
        $a4 = "PasswordsList.txt" ascii fullword
        $a5 = "Software\\Valve\\Steam" wide fullword
    condition:
        all of them
}

