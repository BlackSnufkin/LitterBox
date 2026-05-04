rule Windows_Trojan_Buerloader_c8a60f46 {
    meta:
        author = "Elastic Security"
        id = "c8a60f46-d49a-4566-845b-675fb55c201c"
        fingerprint = "346233f4b1306eb574b4063d3b47f90e65a81ad7fe1c74d2a68640d99d456c4c"
        creation_date = "2021-08-16"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Buerloader"
        reference_sample = "3abed86f46c8be754239f8c878f035efaae91c33b8eb8818c5bbed98c4d9a3ac"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User-Agent: Host:  HTTP/1.1" ascii fullword
        $a2 = "ServerHelloPayloadrandom" ascii fullword
        $a3 = "Bad JSON in payload" ascii fullword
        $a4 = { 7B 22 68 65 6C 6C 6F 22 3A 20 22 77 6F 72 6C 64 22 7D 48 54 54 50 2F 31 2E 31 20 33 30 31 20 46 6F 75 6E 64 }
        $a5 = "PayloadU24UnknownExtensiontyp" ascii fullword
        $a6 = " NTDLL.DLL" wide fullword
    condition:
        all of them
}

