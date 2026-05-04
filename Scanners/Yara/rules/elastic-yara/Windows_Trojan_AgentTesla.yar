rule Windows_Trojan_AgentTesla_d3ac2b2f {
    meta:
        author = "Elastic Security"
        id = "d3ac2b2f-14fc-4851-8a57-41032e386aeb"
        fingerprint = "cbbb56fe6cd7277ae9595a10e05e2ce535a4e6bf205810be0bbce3a883b6f8bc"
        creation_date = "2021-03-22"
        last_modified = "2022-06-20"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "65463161760af7ab85f5c475a0f7b1581234a1e714a2c5a555783bdd203f85f4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GetMozillaFromLogins" ascii fullword
        $a2 = "AccountConfiguration+username" wide fullword
        $a3 = "MailAccountConfiguration" ascii fullword
        $a4 = "KillTorProcess" ascii fullword
        $a5 = "SmtpAccountConfiguration" ascii fullword
        $a6 = "GetMozillaFromSQLite" ascii fullword
        $a7 = "Proxy-Agent: HToS5x" wide fullword
        $a8 = "set_BindingAccountConfiguration" ascii fullword
        $a9 = "doUsernamePasswordAuth" ascii fullword
        $a10 = "SafariDecryptor" ascii fullword
        $a11 = "get_securityProfile" ascii fullword
        $a12 = "get_useSeparateFolderTree" ascii fullword
        $a13 = "get_DnsResolver" ascii fullword
        $a14 = "get_archivingScope" ascii fullword
        $a15 = "get_providerName" ascii fullword
        $a16 = "get_ClipboardHook" ascii fullword
        $a17 = "get_priority" ascii fullword
        $a18 = "get_advancedParameters" ascii fullword
        $a19 = "get_disabledByRestriction" ascii fullword
        $a20 = "get_LastAccessed" ascii fullword
        $a21 = "get_avatarType" ascii fullword
        $a22 = "get_signaturePresets" ascii fullword
        $a23 = "get_enableLog" ascii fullword
        $a24 = "TelegramLog" ascii fullword
        $a25 = "generateKeyV75" ascii fullword
        $a26 = "set_accountName" ascii fullword
        $a27 = "set_InternalServerPort" ascii fullword
        $a28 = "set_bindingConfigurationUID" ascii fullword
        $a29 = "set_IdnAddress" ascii fullword
        $a30 = "set_GuidMasterKey" ascii fullword
        $a31 = "set_username" ascii fullword
        $a32 = "set_version" ascii fullword
        $a33 = "get_Clipboard" ascii fullword
        $a34 = "get_Keyboard" ascii fullword
        $a35 = "get_ShiftKeyDown" ascii fullword
        $a36 = "get_AltKeyDown" ascii fullword
        $a37 = "get_Password" ascii fullword
        $a38 = "get_PasswordHash" ascii fullword
        $a39 = "get_DefaultCredentials" ascii fullword
    condition:
        8 of ($a*)
}

rule Windows_Trojan_AgentTesla_e577e17e {
    meta:
        author = "Elastic Security"
        id = "e577e17e-5c42-4431-8c2d-0c1153128226"
        fingerprint = "009cb27295a1aa0dde84d29ee49b8fa2e7a6cec75eccb7534fec3f5c89395a9d"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 20 4D 27 00 00 33 DB 19 0B 00 07 17 FE 01 2C 02 18 0B 00 07 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_f2a90d14 {
    meta:
        author = "Elastic Security"
        id = "f2a90d14-7212-41a5-a2cd-a6a6dedce96e"
        fingerprint = "829c827069846ba1e1378aba8ee6cdc801631d769dc3dce15ccaacd4068a88a6"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "ed43ddb536e6c3f8513213cd6eb2e890b73e26d5543c0ba1deb2690b5c0385b6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0B FE 01 2C 0B 07 16 7E 08 00 00 04 A2 1F 0C 0C 00 08 1F 09 FE 01 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_a2d69e48 {
    meta:
        author = "Elastic Security"
        id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
        fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
        creation_date = "2023-05-01"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
        $a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_AgentTesla_ebf431a8 {
    meta:
        author = "Elastic Security"
        id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
        fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
        creation_date = "2023-12-01"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.AgentTesla"
        reference = "https://www.elastic.co/security-labs/attack-chain-leads-to-xworm-and-agenttesla"
        reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "MozillaBrowserList"
        $a2 = "EnableScreenLogger"
        $a3 = "VaultGetItem_WIN7"
        $a4 = "PublicIpAddressGrab"
        $a5 = "EnableTorPanel"
        $a6 = "get_GuidMasterKey"
    condition:
        4 of them
}

