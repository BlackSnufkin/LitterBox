rule MacOS_Backdoor_Applejeus_a54e423c {
    meta:
        author = "Elastic Security"
        id = "a54e423c-6467-4c80-9a2a-c868d3323d77"
        fingerprint = "413318971af37b634e5022241b8b6ab85d6cf113902acacbb750a268c1c1fc22"
        creation_date = "2026-02-26"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "8e2b17417cb99e7b689f46ef1c8500a33860e28e497f495c02eece2d4c3217f8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 81 3F 28 00 00 80 74 ?? 8B 4F 04 48 01 CF FF C2 44 39 C2 }
    condition:
        all of them
}

rule MacOS_Backdoor_Applejeus_0152671e {
    meta:
        author = "Elastic Security"
        id = "0152671e-1086-4776-a3ac-87ad6e5d5dcf"
        fingerprint = "4207620255ab5bbb3ebe27d790e282a24987505c42a1876c8092370ee564712c"
        creation_date = "2026-02-27"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "5e54bccbd4d93447e79cda0558b0b308a186c2be571c739e5460a3cb6ef665c0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = "--jeus" fullword
        $b = "%09d-%06d" fullword
        $c = "Reply received"
        $d = "multipart/form-data;boundary=jeus" fullword
    condition:
        all of them
}

rule MacOS_Backdoor_Applejeus_71c0acb0 {
    meta:
        author = "Elastic Security"
        id = "71c0acb0-c326-4d9d-91c6-039560a4b574"
        fingerprint = "25cc2a29480b78c196f919c735918cbb98325f200d68ddc9bfcebc13aa439a21"
        creation_date = "2026-02-27"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Backdoor.Applejeus"
        reference_sample = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 89 C1 83 E1 0F 42 8A 0C 39 41 30 0C 04 48 FF C0 }
        $b = { 41 C7 07 00 00 00 00 BE 00 00 03 00 4C 89 E7 }
    condition:
        all of them
}

