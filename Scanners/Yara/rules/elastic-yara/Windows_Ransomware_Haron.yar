rule Windows_Ransomware_Haron_a1c12e7e {
    meta:
        author = "Elastic Security"
        id = "a1c12e7e-a740-4d26-a0ed-310a2b03fe50"
        fingerprint = "c6abe96bd2848bb489f856373356dbad3fca273e9d71394ec22960070557ad11"
        creation_date = "2021-08-03"
        last_modified = "2021-10-04"
        description = "Direct overlap with Thanos/Avaddon"
        threat_name = "Windows.Ransomware.Haron"
        reference_sample = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 04 28 0E 00 00 0A 06 FE 06 2A 00 00 06 73 0F 00 00 0A 28 }
    condition:
        any of them
}

rule Windows_Ransomware_Haron_23b76cb7 {
    meta:
        author = "Elastic Security"
        id = "23b76cb7-6f96-4012-ad66-2e4e4ae744a9"
        fingerprint = "9dc91a56ef17873f3e833d85fa947facde741d80a574ae911261e553a40a2731"
        creation_date = "2021-08-03"
        last_modified = "2021-10-04"
        description = "Direct overlap with Thanos/Avaddon"
        threat_name = "Windows.Ransomware.Haron"
        reference_sample = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 0A 28 06 00 00 06 26 DE 0A 08 2C 06 08 6F 48 00 00 0A DC DE }
    condition:
        any of them
}

