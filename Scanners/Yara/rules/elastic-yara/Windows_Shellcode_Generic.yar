rule Windows_Shellcode_Generic_8c487e57 {
    meta:
        author = "Elastic Security"
        id = "8c487e57-4b8c-488e-a1d9-786ff935fd2c"
        fingerprint = "834caf96192a513aa93ac48fb8d2f3326bf9f08acaf7a27659f688b26e3e57e4"
        creation_date = "2022-05-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 }
    condition:
        all of them
}

rule Windows_Shellcode_Generic_f27d7beb {
    meta:
        author = "Elastic Security"
        id = "f27d7beb-5ce0-4831-b1ad-320b346612c3"
        fingerprint = "3f8dd6733091ec229e1bebe9e4cd370ad47ab2e3678be4c2d9c450df731a6e5c"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 53 48 89 E3 66 83 E4 00 48 B9 [8] BA 01 00 00 00 41 B8 00 00 00 00 48 B8 [8] FF D0 48 89 DC 5B C3 }
    condition:
        all of them
}

rule Windows_Shellcode_Generic_29dcbf7a {
    meta:
        author = "Elastic Security"
        id = "29dcbf7a-2d3b-4e05-a2be-15623bf62d06"
        fingerprint = "e4664ec7bf7dab3fff873fe4b059e97d2defe3b50e540b96dd98481638dcdcd8"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Shellcode.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { FC 48 83 E4 F0 41 57 41 56 41 55 41 54 55 53 56 57 48 83 EC 40 48 83 EC 40 48 83 EC 40 48 89 E3 }
    condition:
        all of them
}

