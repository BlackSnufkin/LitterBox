rule Windows_Trojan_MyloBot_a895174a {
    meta:
        author = "Elastic Security"
        id = "a895174a-0395-4ccb-b681-e8111a817a5c"
        fingerprint = "dfa1e47260c0e07fea3b2b61157de71f412807b9eec19b14082da7d6a95d6099"
        creation_date = "2024-05-15"
        last_modified = "2024-06-12"
        threat_name = "Windows.Trojan.MyloBot"
        reference_sample = "33831d9ad64d0f52f507f08ef81607aafa6ced58a189969af6cf57c659c982d2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s\\%s.lnk" wide fullword
        $a2 = "%s\\%s.exe" wide fullword
        $a3 = "%s\\%s\\%s.exe" wide fullword
        $a4 = "HTTP/1.0 502" ascii fullword
        $a5 = "/c \"%ws '%ws%s'\"" ascii fullword
        $a6 = ">> %ws %ws %ws" ascii fullword
        $a7 = "%s\\DefaultIcon" ascii fullword
    condition:
        all of them
}

