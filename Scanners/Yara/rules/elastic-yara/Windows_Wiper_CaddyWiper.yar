rule Windows_Wiper_CaddyWiper_484bd98a {
    meta:
        author = "Elastic Security"
        id = "484bd98a-543f-42de-a58c-fe9c7b5605a3"
        fingerprint = "de16515a72cd1f7b4d7ee46a4fafde07cf224c2b6df9037bcd20ab4d39181fa8"
        creation_date = "2022-03-14"
        last_modified = "2022-04-12"
        threat_name = "Windows.Wiper.CaddyWiper"
        reference_sample = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { C6 45 AC 43 C6 45 AD 3A C6 45 AE 5C C6 45 AF 55 C6 45 B0 73 C6 45 B1 65 C6 45 B2 72 C6 45 B3 73 }
        $a2 = { C6 45 E0 44 C6 45 E1 3A C6 45 E2 5C }
        $a3 = { C6 45 9C 6E C6 45 9D 65 C6 45 9E 74 C6 45 9F 61 C6 45 A0 70 C6 45 A1 69 C6 45 A2 33 C6 45 A3 32 }
        $s1 = "DsRoleGetPrimaryDomainInformation"
    condition:
        all of them
}

