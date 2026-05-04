rule Windows_Hacktool_Phant0m_2d6f9b57 {
    meta:
        author = "Elastic Security"
        id = "2d6f9b57-bde0-4570-8e38-187dbf05e6d3"
        fingerprint = "d4a92775e76bbb00e677a289942f9b3f8101a1dc2f55b30cfa32e4c7feae6c8a"
        creation_date = "2024-02-28"
        last_modified = "2024-03-21"
        threat_name = "Windows.Hacktool.Phant0m"
        reference_sample = "30978aadd7d7bc86e735facb5046942792ad1beab6919754e6765e0ccbcf89d6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $api = "NtQueryInformationThread"
        $s1 = "Suspending EventLog thread %d with start address %p"
        $s2 = "Found the EventLog Module (wevtsvc.dll) at %p"
        $s3 = "Event Log service PID detected as %d."
        $s4 = "Thread %d is detected and successfully killed."
        $s5 = "Windows EventLog module %S at %p"
    condition:
        $api and 2 of ($s*)
}

