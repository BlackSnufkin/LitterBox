rule Windows_Trojan_Netwire_6a7df287 {
    meta:
        author = "Elastic Security"
        id = "6a7df287-1656-4779-9a96-c0ab536ae86a"
        fingerprint = "85051a0b94da4388eaead4c4f4b2d16d4a5eb50c3c938b3daf5c299c9c12f1e6"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Netwire"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }
    condition:
        all of them
}

rule Windows_Trojan_Netwire_1b43df38 {
    meta:
        author = "Elastic Security"
        id = "1b43df38-886e-4f58-954a-a09f30f19907"
        fingerprint = "4142ea14157939dc23b8d1f5d83182aef3a5877d2506722f7a2706b7cb475b76"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Netwire"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword
        $a2 = "\\Login Data"
        $a3 = "SOFTWARE\\NetWire" fullword
    condition:
        2 of them
}

rule Windows_Trojan_Netwire_f85e4abc {
    meta:
        author = "Elastic Security"
        id = "f85e4abc-f2d7-491b-a1ad-a59f287e5929"
        fingerprint = "66cae88c9f8b975133d2b3af94a869244d273021261815b15085c638352bf2ca"
        creation_date = "2022-08-14"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Netwire"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C9 0F 44 C8 D0 EB 8A 44 24 12 0F B7 C9 75 D1 32 C0 B3 01 8B CE 88 44 }
    condition:
        all of them
}

rule Windows_Trojan_Netwire_f42cb379 {
    meta:
        author = "Elastic Security"
        id = "f42cb379-ac8c-4790-a6d3-aad6dc4acef6"
        fingerprint = "a52d2be082d57d07ab9bb9087dd258c29ef0528c4207ac6b31832f975a1395b6"
        creation_date = "2022-08-14"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Netwire"
        reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
        reference_sample = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "http://%s%ComSpec" ascii fullword
        $a2 = "%c%.8x%s" ascii fullword
        $a3 = "%6\\6Z65dlNh\\YlS.dfd" ascii fullword
        $a4 = "GET %s HTTP/1.1" ascii fullword
        $a5 = "R-W65: %6:%S" ascii fullword
        $a6 = "PTLLjPq %6:%S -qq9/G.y" ascii fullword
    condition:
        4 of them
}

