rule Windows_Trojan_SVCReady_af498d39 {
    meta:
        author = "Elastic Security"
        id = "af498d39-6ae8-46de-ad6c-81b346d80139"
        fingerprint = "6e30d9977698c7864a8c264a7fe8c9a558f6e51dda9c887bda94261ce187645f"
        creation_date = "2022-06-12"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.SVCReady"
        reference_sample = "08e427c92010a8a282c894cf5a77a874e09c08e283a66f1905c131871cc4d273"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "RunPEDllNative::HookNtCreateUserProcess fail: targetMapping.valid" ascii fullword
        $a2 = "Section Mapping error:Process=0x%x Section [%s] res[0x%x] != va[0x%x] Status:%u" ascii fullword
        $a3 = "%s - %I64d < %I64d > %I64d clicks, %I64d pixels, ready=%i" ascii fullword
        $a4 = "Svc:windowThreadRunner done" ascii fullword
        $a5 = "svc commonMain" ascii fullword
    condition:
        4 of them
}

