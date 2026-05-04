rule Windows_Trojan_Trickbot_01365e46 {
    meta:
        author = "Elastic Security"
        id = "01365e46-c769-4c6e-913a-4d1e42948af2"
        fingerprint = "98505c3418945c10bf4f50a183aa49bdbc7c1c306e98132ae3d0fc36e216f191"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "5c450d4be39caef1d9ec943f5dfeb6517047175fec166a52970c08cd1558e172"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 43 28 4C 8B 53 18 4C 8B 5B 10 4C 8B 03 4C 8B 4B 08 89 44 24 38 48 89 4C 24 30 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_06fd4ac4 {
    meta:
        author = "Elastic Security"
        id = "06fd4ac4-1155-4068-ae63-4d83db2bd942"
        fingerprint = "ece49004ed1d27ef92b3b1ec040d06e90687d4ac5a89451e2ae487d92cb24ddd"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        description = "Identifies Trickbot unpacker"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_ce4305d1 {
    meta:
        author = "Elastic Security"
        id = "ce4305d1-8a6f-4797-afaf-57e88f3d38e6"
        fingerprint = "ae606e758b02ccf2a9a313aebb10773961121f79a94c447e745289ee045cf4ee"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { F9 8B 45 F4 89 5D E4 85 D2 74 39 83 C0 02 03 C6 89 45 F4 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_1e56fad7 {
    meta:
        author = "Elastic Security"
        id = "1e56fad7-383f-4ee0-9f8f-a0b3dcceb691"
        fingerprint = "a0916134f47df384bbdacff994970f60d3613baa03c0a581b7d1dd476af3121b"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_93c9a2a4 {
    meta:
        author = "Elastic Security"
        id = "93c9a2a4-a07a-4ed4-a899-b160d235bf50"
        fingerprint = "0ff82bf9e70304868ff033f0d96e2a140af6e40c09045d12499447ffb94ab838"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_5340afa3 {
    meta:
        author = "Elastic Security"
        id = "5340afa3-ff90-4f61-a1ac-aba1f32dd375"
        fingerprint = "7da4726ccda6a76d2da773d41f012763802d586f64a313c1c37733905ae9da81"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E8 0C 89 5D F4 0F B7 DB 03 5D 08 66 83 F8 03 75 0A 8B 45 14 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_e7932501 {
    meta:
        author = "Elastic Security"
        id = "e7932501-66bf-4713-b10e-bcda29f4b901"
        fingerprint = "ae31b49266386a6cf42289a08da4a20fc1330096be1dae793de7b7230225bfc7"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 24 0C 01 00 00 00 85 C0 7C 2F 3B 46 24 7D 2A 8B 4E 20 8D 04 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cd0868d5 {
    meta:
        author = "Elastic Security"
        id = "cd0868d5-42d8-437f-8c1a-303526c08442"
        fingerprint = "2f777285a90fce20cd4eab203f3ec7ed1c62e09fc2dfdce09b57e0802f49628f"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8D 1C 01 89 54 24 10 8B 54 24 1C 33 C9 66 8B 0B 8D 3C 8A 8B 4C }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_515504e2 {
    meta:
        author = "Elastic Security"
        id = "515504e2-6b7f-4398-b89b-3af2b46c78a7"
        fingerprint = "8eb741e1b3bd760e2cf511ad6609ac6f1f510958a05fb093eae26462f16ee1d0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_a0fc8f35 {
    meta:
        author = "Elastic Security"
        id = "a0fc8f35-cbeb-43a8-b00d-7a0f981e84e4"
        fingerprint = "033ff4f47fece45dfa7e3ba185df84a767691e56f0081f4ed96f9e2455a563cb"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_cb95dc06 {
    meta:
        author = "Elastic Security"
        id = "cb95dc06-6383-4487-bf10-7fd68d61e37a"
        fingerprint = "0d28f570db007a1b91fe48aba18be7541531cceb7f11a6a4471e92abd55b3b90"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 5F 5E 33 C0 5B 5D C3 8B 55 14 89 02 8B 45 18 5F 89 30 B9 01 00 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_9d4d3fa4 {
    meta:
        author = "Elastic Security"
        id = "9d4d3fa4-4e37-40d7-8399-a49130b7ef49"
        fingerprint = "b06c3c7ba1f5823ce381971ed29554e5ddbe327b197de312738165ee8bf6e194"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 89 44 24 18 33 C9 89 44 24 1C 8D 54 24 38 89 44 24 20 33 F6 89 44 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_34f00046 {
    meta:
        author = "Elastic Security"
        id = "34f00046-8938-4103-91ec-4a745a627d4a"
        fingerprint = "5c6f11e2a040ae32336f4b4c4717e0f10c73359899302b77e1803f3a609309c0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_f2a18b09 {
    meta:
        author = "Elastic Security"
        id = "f2a18b09-f7b3-4d1a-87ab-3018f520b69c"
        fingerprint = "3e4474205efe22ea0185c49052e259bc08de8da7c924372f6eb984ae36b91a1c"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 04 39 45 08 75 08 8B 4D F8 8B 41 18 EB 0F 8B 55 F8 8B 02 89 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_d916ae65 {
    meta:
        author = "Elastic Security"
        id = "d916ae65-c97b-495c-89c2-4f1ec90081d2"
        fingerprint = "2e109ed59a1e759ef089e04c21016482bf70228da30d8b350fc370b4e4d120e0"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 5F 24 01 10 CF 22 01 10 EC 22 01 10 38 23 01 10 79 23 01 10 82 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_52722678 {
    meta:
        author = "Elastic Security"
        id = "52722678-afbe-43ec-a39b-6848b7d49488"
        fingerprint = "e67dda5227be74424656957843777ea533b6800576fd85f978fd8fb50504209c"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 2B 5D 0C 89 5D EC EB 03 8B 5D EC 8A 1C 3B 84 DB 74 0D 38 1F }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_28a60148 {
    meta:
        author = "Elastic Security"
        id = "28a60148-2efb-4cd2-ada1-dd2ae2699adf"
        fingerprint = "c857aa792ef247bfcf81e75fb696498b1ba25c09fc04049223a6dfc09cc064b1"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { C0 31 E8 83 7D 0C 00 89 44 24 38 0F 29 44 24 20 0F 29 44 24 10 0F 29 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_997b25a0 {
    meta:
        author = "Elastic Security"
        id = "997b25a0-aeac-4f74-aa87-232c4f8329b6"
        fingerprint = "0bba1c5284ed0548f51fdfd6fb96e24f92f7f4132caefbf0704efb0b1a64b7c4"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_b17b33a1 {
    meta:
        author = "Elastic Security"
        id = "b17b33a1-1021-4980-8ffd-2e7aa4ca2ae4"
        fingerprint = "753d15c1ff0cc4cf75250761360bb35280ff0a1a4d34320df354e0329dd35211"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_23d77ae5 {
    meta:
        author = "Elastic Security"
        id = "23d77ae5-80de-4bb0-8701-ddcaff443dcc"
        fingerprint = "d382a99e5eed87cf2eab5e238e445ca0bf7852e40b0dd06a392057e76144699f"
        creation_date = "2021-03-28"
        last_modified = "2021-08-23"
        description = "Targets importDll64 containing Browser data stealer module"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "844974A2D3266E1F9BA275520C0E8A5D176DF69A0CCD5135B99FACF798A5D209"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/system32/cmd.exe /c \"start microsoft-edge:{URL}\"" ascii fullword
        $a2 = "SELECT name, value, host_key, path, expires_utc, creation_utc, encrypted_value FROM cookies" ascii fullword
        $a3 = "attempt %d. Cookies not found" ascii fullword
        $a4 = "attempt %d. History not found" ascii fullword
        $a5 = "Cookies version is %d (%d)" ascii fullword
        $a6 = "attempt %d. Local Storage not found" ascii fullword
        $a7 = "str+='xie.com.'+p+'.guid='+'{'+components[i]+'}\\n';" ascii fullword
        $a8 = "Browser exec is: %s" ascii fullword
        $a9 = "found mozilla key: %s" ascii fullword
        $a10 = "Version %d is not supported" ascii fullword
        $a11 = "id %d - %s" ascii fullword
        $a12 = "prot: %s, scope: %s, port: %d" ascii fullword
        $a13 = "***** Send %d bytes to callback from %s *****" ascii fullword
        $a14 = "/chrome.exe {URL}" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_5574be7d {
    meta:
        author = "Elastic Security"
        id = "5574be7d-7502-4357-8110-2fb4a661b2bd"
        fingerprint = "23d9b89917a0fc5aad903595b89b650f6dbb0f82ce28ce8bcc891904f62ccf1b"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets injectDll64 containing injection functionality to steal banking credentials"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "8c5c0d27153f60ef8aec57def2f88e3d5f9a7385b5e8b8177bab55fa7fac7b18"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "webinject64.dll" ascii fullword
        $a2 = "Mozilla Firefox version: %s" ascii fullword
        $a3 = "socks=127.0.0.1:" ascii fullword
        $a4 = "<conf ctl=\"dpost\" file=\"dpost\" period=\"60\"/>" ascii fullword
        $a5 = "<moduleconfig>" ascii fullword
        $a6 = "https://%.*s%.*s" ascii fullword
        $a7 = "http://%.*s%.*s" ascii fullword
        $a8 = "Chrome version: %s" ascii fullword
        $a9 = "IE version real: %s" ascii fullword
        $a10 = "IE version old: %s" ascii fullword
        $a11 = "Build date: %s %s" ascii fullword
        $a12 = "EnumDpostServer" ascii fullword
        $a13 = "ESTR_PASS_" ascii fullword
        $a14 = "<conf ctl=\"dinj\" file=\"dinj\" period=\"20\"/>" ascii fullword
        $a15 = "<conf ctl=\"sinj\" file=\"sinj\" period=\"20\"/>" ascii fullword
        $a16 = "<autoconf>" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_1473f0b4 {
    meta:
        author = "Elastic Security"
        id = "1473f0b4-a6b5-4b19-a07e-83d32a7e44a0"
        fingerprint = "15438ae141a2ac886b1ba406ba45119da1a616c3b2b88da3f432253421aa8e8b"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets mailsearcher64.dll module"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "9cfb441eb5c60ab1c90b58d4878543ee554ada2cceee98d6b867e73490d30fec"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "mailsearcher.dll" ascii fullword
        $a2 = "%s/%s/%s/send/" wide fullword
        $a3 = "Content-Disposition: form-data; name=\"list\"" ascii fullword
        $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autostart>no</autostart><autoconf><conf ctl=\"SetConf\" file=\"mail"
        $a5 = "eriod=\"60\"/></autoconf></moduleconfig>" ascii fullword
        $a6 = "=Waitu H" ascii fullword
        $a7 = "Content-Length: %d" ascii fullword
    condition:
        2 of ($a*)
}

rule Windows_Trojan_Trickbot_dcf25dde {
    meta:
        author = "Elastic Security"
        id = "dcf25dde-36c4-4a24-aa2b-0b3f42324918"
        fingerprint = "4088ae29cb3b665ccedf69e9d02c1ff58620d4b589343cd4077983b25c5b479f"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets networkDll64.dll module containing functionality to gather network and system information"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "BA2A255671D33677CAB8D93531EB25C0B1F1AC3E3085B95365A017463662D787"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Host Name - %s" wide fullword
        $a2 = "Last Boot Up Time - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
        $a3 = "Install Date - %02u/%02u/%04u %02d.%02d.%02d" wide fullword
        $a4 = "System Directory - %s" wide fullword
        $a5 = "OS Version - %s" wide fullword
        $a6 = "***PROCESS LIST***" wide fullword
        $a7 = "Product Type - Domain Controller" wide fullword
        $a8 = "Registered Organization - %s" wide fullword
        $a9 = "Product Type - Domain Controller" wide fullword
        $a10 = "Build Type - %s" wide fullword
        $a11 = "Boot Device - %s" wide fullword
        $a12 = "Serial Number - %s" wide fullword
        $a13 = "OS Architecture - %s" wide fullword
        $a14 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"1440\"/></au"
        $a15 = "oduleconfig>" ascii fullword
        $a16 = "Computer name: %s" wide fullword
        $a17 = "/c net view /all /domain" ascii fullword
        $a18 = "/c nltest /domain_trusts" ascii fullword
        $a19 = "***SYSTEMINFO***" wide fullword
        $a20 = "***LOCAL MACHINE DATA***" wide fullword
        $a21 = "Admin Name: %s" wide fullword
        $a22 = "Domain controller: %s" wide fullword
        $a23 = "Admin E-mail: %s" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_46dc12dd {
    meta:
        author = "Elastic Security"
        id = "46dc12dd-d81a-43a6-b7c3-f59afa1c863e"
        fingerprint = "997fe1c5a06bfffb754051436c48a0538ff2dcbfddf0d865c3a3797252247946"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets newBCtestDll64 module containing reverse shell functionality"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "BF38A787AEE5AFDCAB00B95CCDF036BC7F91F07151B4444B54165BB70D649CE5"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "setconf" ascii fullword
        $a2 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
        $a3 = "nf\" file = \"bcconfig\" period = \"90\"/></autoconf></moduleconfig>" ascii fullword
        $a4 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name = \"id\"/><needinfo name = \"ip\"/><autoconf><conf ctl = \""
        $a5 = "<addr>" ascii fullword
        $a6 = "</addr>" ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_78a26074 {
    meta:
        author = "Elastic Security"
        id = "78a26074-dc4b-436d-8188-2a3cfdabf6db"
        fingerprint = "f0446c7e1a497b93720824f4a5b72f23f00d0ee9a1607bc0c1b097109ec132a8"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets psfin64.dll module containing point-of-sale recon functionality"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "8CD75FA8650EBCF0A6200283E474A081CC0BE57307E54909EE15F4D04621DDE0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"14400\"/></a"
        $a2 = "Dpost servers unavailable" ascii fullword
        $a3 = "moduleconfig>" ascii fullword
        $a4 = "ALOHA found: %d" wide fullword
        $a5 = "BOH found: %d" wide fullword
        $a6 = "MICROS found: %d" wide fullword
        $a7 = "LANE found: %d" wide fullword
        $a8 = "RETAIL found: %d" wide fullword
        $a9 = "REG found: %d" wide fullword
        $a10 = "STORE found: %d" wide fullword
        $a11 = "POS found: %d" wide fullword
        $a12 = "DOMAIN %s" wide fullword
        $a13 = "/%s/%s/90" wide fullword
        $a14 = "CASH found: %d" wide fullword
        $a15 = "COMPUTERS:" wide fullword
        $a16 = "TERM found: %d" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_217b9c97 {
    meta:
        author = "Elastic Security"
        id = "217b9c97-a637-49b8-a652-5a42ea19ee8e"
        fingerprint = "7d5dcb60526a80926bbaa7e3cd9958719e326a160455095ff9f0315e85b8adf6"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets pwgrab64.dll module containing functionality use to retrieve local passwords"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "1E90A73793017720C9A020069ED1C87879174C19C3B619E5B78DB8220A63E9B7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "pwgrab.dll" ascii fullword
        $a2 = "\\\\.\\pipe\\pidplacesomepipe" ascii fullword
        $a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii fullword
        $a4 = "select origin_url, username_value, password_value, length(password_value) from logins where blacklisted_by_user = 0" ascii fullword
        $a5 = "<moduleconfig><autostart>yes</autostart><all>yes</all><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
        $a6 = "Grab_Passwords_Chrome(0)" ascii fullword
        $a7 = "Grab_Passwords_Chrome(1)" ascii fullword
        $a8 = "=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" ascii fullword
        $a9 = "Grab_Passwords_Chrome(): Can't open database" ascii fullword
        $a10 = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_"
        $a11 = "Chrome login db copied" ascii fullword
        $a12 = "Skip Chrome login db copy" ascii fullword
        $a13 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
        $a14 = "Grab_Passwords_Chrome() success" ascii fullword
        $a15 = "No password provided by user" ascii fullword
        $a16 = "Chrome login db should be copied (copy absent)" ascii fullword
        $a17 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_d2110921 {
    meta:
        author = "Elastic Security"
        id = "d2110921-b957-49b7-8a26-4c0b7d1d58ad"
        fingerprint = "55dbbcbc77ec51a378ad2ba8d56cb0811d23b121cacd037503fd75d08529c5b5"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets shareDll64.dll module containing functionality use to spread Trickbot across local networks"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "05EF40F7745DB836DE735AC73D6101406E1D9E58C6B5F5322254EB75B98D236A"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "module64.dll" ascii fullword
        $a2 = "Size - %d kB" ascii fullword
        $a3 = "%s - FAIL" wide fullword
        $a4 = "%s - SUCCESS" wide fullword
        $a5 = "ControlSystemInfoService" ascii fullword
        $a6 = "<moduleconfig><autostart>yes</autostart></moduleconfig>" ascii fullword
        $a7 = "Copy: %d" wide fullword
        $a8 = "Start sc 0x%x" wide fullword
        $a9 = "Create sc 0x%x" wide fullword
        $a10 = "Open sc %d" wide fullword
        $a11 = "ServiceInfoControl" ascii fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_0114d469 {
    meta:
        author = "Elastic Security"
        id = "0114d469-8731-4f4f-8657-49cded5efadb"
        fingerprint = "4f1fa072f4ba577d590bb8946ea9b9774aa291cb2406f13be5932e97e8e760c6"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets systeminfo64.dll module containing functionality use to retrieve system information"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "083CB35A7064AA5589EFC544AC1ED1B04EC0F89F0E60383FCB1B02B63F4117E9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<user>%s</user>" wide fullword
        $a2 = "<service>%s</service>" wide fullword
        $a3 = "<users>" wide fullword
        $a4 = "</users>" wide fullword
        $a5 = "%s%s%s</general>" wide fullword
        $a6 = "<program>%s</program>" wide fullword
        $a7 = "<moduleconfig><autostart>no</autostart><limit>2</limit></moduleconfig>" ascii fullword
        $a8 = "<cpu>%s</cpu>" wide fullword
        $a9 = "<ram>%s</ram>" wide fullword
        $a10 = "</installed>" wide fullword
        $a11 = "<installed>" wide fullword
        $a12 = "<general>" wide fullword
        $a13 = "SELECT * FROM Win32_Processor" wide fullword
        $a14 = "SELECT * FROM Win32_OperatingSystem" wide fullword
        $a15 = "SELECT * FROM Win32_ComputerSystem" wide fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_Trickbot_07239dad {
    meta:
        author = "Elastic Security"
        id = "07239dad-7f9e-4b20-a691-d9538405b931"
        fingerprint = "32d63b8db4307fd67e2c9068e22f843f920f19279c4a40e17cd14943577e7c81"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets vncDll64.dll module containing remote control VNC functionality"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "DBD534F2B5739F89E99782563062169289F23AA335639A9552173BEDC98BB834"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\MaxMikhaylov\\Documents\\Visual Studio 2010\\MMVNC.PROXY\\VNCSRV\\x64\\Release\\VNCSRV.pdb" ascii fullword
        $a2 = "vncsrv.dll" ascii fullword
        $a3 = "-new -noframemerging http://www.google.com" ascii fullword
        $a4 = "IE.HTTP\\shell\\open\\command" ascii fullword
        $a5 = "EDGE\\shell\\open\\command" ascii fullword
        $a6 = "/K schtasks.exe |more" ascii fullword
        $a7 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig> " ascii fullword
        $a8 = "\\Microsoft Office\\Office16\\outlook.exe" ascii fullword
        $a9 = "\\Microsoft Office\\Office11\\outlook.exe" ascii fullword
        $a10 = "\\Microsoft Office\\Office15\\outlook.exe" ascii fullword
        $a11 = "\\Microsoft Office\\Office12\\outlook.exe" ascii fullword
        $a12 = "\\Microsoft Office\\Office14\\outlook.exe" ascii fullword
        $a13 = "TEST.TEMP:" ascii fullword
        $a14 = "Chrome_WidgetWin" wide fullword
        $a15 = "o --disable-gpu --disable-d3d11 --disable-accelerated-2d-canvas" ascii fullword
        $a16 = "NetServerStart" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_Trickbot_fd7a39af {
    meta:
        author = "Elastic Security"
        id = "fd7a39af-c6ea-4682-a00a-01f775c3bb8d"
        fingerprint = "3f2e654f2ffdd940c27caec3faeb4bda24c797a17d0987378e36c1e16fadc772"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets wormDll64.dll module containing spreading functionality"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "D5BB8D94B71D475B5EB9BB4235A428563F4104EA49F11EF02C8A08D2E859FD68"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "module64.dll" ascii fullword
        $a2 = "worming.png" wide
        $a3 = "Size - %d kB" ascii fullword
        $a4 = "[+] %s -" wide fullword
        $a5 = "%s\\system32" ascii fullword
        $a6 = "[-] %s" wide fullword
        $a7 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/></moduleconfig>" ascii fullword
        $a8 = "*****MACHINE IN WORKGROUP*****" wide fullword
        $a9 = "*****MACHINE IN DOMAIN*****" wide fullword
        $a10 = "\\\\%s\\IPC$" ascii fullword
        $a11 = "Windows 5" ascii fullword
        $a12 = "InfMach" ascii fullword
        $a13 = "%s x64" wide fullword
        $a14 = "%s x86" wide fullword
        $a15 = "s(&(objectCategory=computer)(userAccountControl:" wide fullword
        $a16 = "------MACHINE IN D-N------" wide fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_2d89e9cd {
    meta:
        author = "Elastic Security"
        id = "2d89e9cd-2941-4b20-ab4e-a487d329ff76"
        fingerprint = "e6eea38858cfbbe5441b1f69c5029ff9279e7affa51615f6c91981fe656294fc"
        creation_date = "2021-03-29"
        last_modified = "2021-08-23"
        description = "Targets tabDll64.dll module containing functionality using SMB for lateral movement"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "3963649ebfabe8f6277190be4300ecdb68d4b497ac5f81f38231d3e6c862a0a8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" ascii fullword
        $a2 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" ascii fullword
        $a3 = "%SystemRoot%\\system32\\stsvc.exe" ascii fullword
        $a4 = "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p" ascii fullword
        $a5 = "DLL and target process must be same architecture" ascii fullword
        $a6 = "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" ascii fullword
        $a7 = "%SystemDrive%\\stsvc.exe" ascii fullword
        $a8 = "Wrote shellcode to 0x%x" ascii fullword
        $a9 = "ERROR: %d, line - %d" wide fullword
        $a10 = "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p" ascii fullword
        $a11 = "GetProcessPEB:EXCEPT" wide fullword
        $a12 = "Checked count - %i, connected count %i" wide fullword
        $a13 = "C:\\%s\\%s C:\\%s\\%s" ascii fullword
        $a14 = "C:\\%s\\%s" ascii fullword
        $a15 = "%s\\ADMIN$\\stsvc.exe" wide fullword
        $a16 = "%s\\C$\\stsvc.exe" wide fullword
        $a17 = "Size - %d kB" ascii fullword
        $a18 = "<moduleconfig><autostart>yes</autostart><sys>yes</sys><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
        $a19 = "%s - FAIL" wide fullword
        $a20 = "%s - SUCCESS" wide fullword
        $a21 = "CmainSpreader::init() CreateEvent, error code %i" wide fullword
        $a22 = "Incorrect ModuleHandle %i, expect %i" wide fullword
        $a23 = "My interface is \"%i.%i.%i.%i\", mask \"%i.%i.%i.%i\"" wide fullword
        $a24 = "WormShare" ascii fullword
        $a25 = "ModuleHandle 0x%08X, call Control: error create thread %i" wide fullword
        $a26 = "Enter to Control: moduleHandle 0x%08X, unknown Ctl = \"%S\"" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_32930807 {
    meta:
        author = "Elastic Security"
        id = "32930807-30bb-4c57-8e17-0da99a816405"
        fingerprint = "0aeb68977f4926272f27d5fba44e66bdbb9d6a113da5d7b4133a379b06df4474"
        creation_date = "2021-03-30"
        last_modified = "2021-10-04"
        description = "Targets cookiesdll.dll module containing functionality used to retrieve browser cookie data"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "e999b83629355ec7ff3b6fda465ef53ce6992c9327344fbf124f7eb37808389d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "select name, encrypted_value, host_key, path, length(encrypted_value), creation_utc, expires_utc from cookies where datetime(exp"
        $a2 = "Cookies send failure: servers unavailable" ascii fullword
        $a3 = "<moduleconfig>"
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_618b27d2 {
    meta:
        author = "Elastic Security"
        id = "618b27d2-22ad-4542-86ed-7148f17971da"
        fingerprint = "df4336e5cbca495dac4fe110bd7a727e91bb3d465f76d3f3796078332c13633c"
        creation_date = "2021-03-30"
        last_modified = "2021-08-23"
        description = "Targets Outlook.dll module containing functionality used to retrieve Outlook data"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "d3ec8f4a46b21fb189fc3d58f3d87bf9897653ecdf90b7952dcc71f3b4023b4e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "OutlookX32.dll" ascii fullword
        $a2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" wide fullword
        $a3 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" wide fullword
        $a4 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" wide fullword
        $a5 = "OutlookX32" ascii fullword
        $a6 = " Port:" wide fullword
        $a7 = " User:" wide fullword
        $a8 = " Pass:" wide fullword
        $a9 = "String$" ascii fullword
        $a10 = "outlookDecrU" ascii fullword
        $a11 = "Cannot Decrypt" ascii fullword
        $a12 = " Mail:" wide fullword
        $a13 = " Serv:" wide fullword
        $a14 = ",outlookDecr" ascii fullword
        $a15 = "CryptApi" ascii fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_6eb31e7b {
    meta:
        author = "Elastic Security"
        id = "6eb31e7b-9dc3-48ff-91fe-8c584729c415"
        fingerprint = "d145b7c95bca0dc0c46a8dff60341a21dce474edd169dd0ee5ea2396dad60b92"
        creation_date = "2021-03-30"
        last_modified = "2021-10-04"
        description = "Targets DomainDll module containing functionality using LDAP to retrieve credentials and configuration information"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "3e3d82ea4764b117b71119e7c2eecf46b7c2126617eafccdfc6e96e13da973b1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "module32.dll" ascii fullword
        $a2 = "Size - %d kB" ascii fullword
        $a3 = "</moduleconfig> " ascii fullword
        $a4 = "<moduleconfig>" ascii fullword
        $a5 = "\\\\%ls\\SYSVOL\\%ls" wide fullword
        $a6 = "DomainGrabber"
        $a7 = "<autostart>yes</autostart>" ascii fullword
        $a8 = "<needinfo name=\"id\"/>" ascii fullword
        $a9 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide fullword
    condition:
        5 of ($a*)
}

rule Windows_Trojan_Trickbot_91516cf4 {
    meta:
        author = "Elastic Security"
        id = "91516cf4-c826-4d5d-908f-e1c0b3bccec5"
        fingerprint = "2667c7181fb4db3f5765369fc2ec010b807a7bf6e2878fc42af410f036c61cbe"
        creation_date = "2021-03-30"
        last_modified = "2021-08-31"
        description = "Generic signature used to identify Trickbot module usage"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "6cd0d4666553fd7184895502d48c960294307d57be722ebb2188b004fc1a8066"
        severity = 80
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<moduleconfig>" ascii wide
        $a2 = "<autostart>" ascii wide
        $a3 = "</autostart>" ascii wide
        $a4 = "</moduleconfig>" ascii wide
    condition:
        all of them
}

rule Windows_Trojan_Trickbot_be718af9 {
    meta:
        author = "Elastic Security"
        id = "be718af9-5995-4ae2-ba55-504e88693c96"
        fingerprint = "047b1c64b8be17d4a6030ab2944ad715380f53a8a6dd9c8887f198693825a81d"
        creation_date = "2021-03-30"
        last_modified = "2021-08-23"
        description = "Targets permadll module used to fingerprint BIOS/firmaware data"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "c1f1bc58456cff7413d7234e348d47a8acfdc9d019ae7a4aba1afc1b3ed55ffa"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "user_platform_check.dll" ascii fullword
        $a2 = "<moduleconfig><nohead>yes</nohead></moduleconfig>" ascii fullword
        $a3 = "DDEADFDEEEEE"
        $a4 = "\\`Ruuuuu_Exs|_" ascii fullword
        $a5 = "\"%pueuu%" ascii fullword
    condition:
        3 of ($a*)
}

rule Windows_Trojan_Trickbot_f8dac4bc {
    meta:
        author = "Elastic Security"
        id = "f8dac4bc-2ea1-4733-a260-59f3cae2eba8"
        fingerprint = "256daf823f6296ae02103336817dec565129a11f37445b791b2f8e3163f0c17f"
        creation_date = "2021-03-30"
        last_modified = "2021-08-23"
        description = "Targets rdpscan module used to bruteforce RDP"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "13d102d546b9384f944f2a520ba32fb5606182bed45a8bba681e4374d7e5e322"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "rdpscan.dll" ascii fullword
        $a2 = "F:\\rdpscan\\Bin\\Release_nologs\\"
        $a3 = "Cookie: %s %s" wide fullword
        $a4 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
        $a5 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"srv\" file=\"srv\" period=\"60\"/></autoconf><"
        $a6 = "X^Failed to create a list of contr" ascii fullword
        $a7 = "rdp/domains" wide fullword
        $a8 = "Your product name" wide fullword
        $a9 = "rdp/over" wide fullword
        $a10 = "rdp/freq" wide fullword
        $a11 = "rdp/names" wide fullword
        $a12 = "rdp/dict" wide fullword
        $a13 = "rdp/mode" wide fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_Trickbot_9c0fa8fe {
    meta:
        author = "Elastic Security"
        id = "9c0fa8fe-8d5f-4581-87a0-92a4ed1b32b3"
        fingerprint = "bd49ed2ee65ff0cfa95efc9887ed24de3882c5b5740d0efc6b9690454ca3f5dc"
        creation_date = "2021-07-13"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Trickbot"
        reference_sample = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }
    condition:
        all of them
}

