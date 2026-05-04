rule Windows_Trojan_Generic_a681f24a {
    meta:
        author = "Elastic Security"
        id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
        fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
        severity = 25
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "_kasssperskdy" wide fullword
        $b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
        $c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword
    condition:
        2 of them
}

rule Windows_Trojan_Generic_ae824b13 : ref1296 {
    meta:
        author = "Elastic Security"
        id = "ae824b13-eaae-49e6-a965-ff10379f3c41"
        fingerprint = "8658996385aac060ebe9eab45bbea8b05b9008926bb3085e5589784473bc3086"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 31 31 34 2E 31 31 34 2E 31 31 34 2E 31 31 34 }
        $a2 = { 69 6E 66 6F 40 63 69 61 2E 6F 72 67 30 }
        $a3 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 30 2E 30 2E 32 36 36 31 2E 39 34 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
        $a4 = { 75 73 65 72 25 33 64 61 64 6D 69 6E 25 32 36 70 61 73 73 77 6F 72 64 25 33 64 64 65 66 61 75 6C 74 25 34 30 72 6F 6F 74 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_eb47e754 : ref1296 {
    meta:
        author = "Elastic Security"
        id = "eb47e754-9b4d-45e7-b76c-027d03326c6c"
        fingerprint = "b71d13a34e5f791612ed414b8b0e993b1f476a8398a1b0be39046914ac5ac21d"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 41 20 61 74 20 4C 20 25 64 }
        $a2 = { 74 63 70 69 70 5F 74 68 72 65 61 64 }
        $a3 = { 32 30 38 2E 36 37 2E 32 32 32 2E 32 32 32 }
        $a4 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 37 2E 30 2E 32 39 38 37 2E 31 33 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        3 of them
}

rule Windows_Trojan_Generic_c7fd8d38 {
    meta:
        author = "Elastic Security"
        id = "c7fd8d38-eaba-424d-b91a-098c439dab6b"
        fingerprint = "dc14cd519b3bbad7c2e655180a584db0a4e2ad4eea073a52c94b0a88152b37ba"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PCREDENTIAL" ascii fullword
        $a2 = "gHotkey" ascii fullword
        $a3 = "EFORMATEX" ascii fullword
        $a4 = "ZLibEx" ascii fullword
        $a5 = "9Root!" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_bbe6c282 {
    meta:
        author = "Elastic Security"
        id = "bbe6c282-e92d-4021-bdaf-189337e4abf0"
        fingerprint = "e004d77440a86c23f23086e1ada6d1453178b9c2292782c1c88a7b14151c10fe"
        creation_date = "2022-03-02"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }
    condition:
        all of them
}

rule Windows_Trojan_Generic_889b1248 {
    meta:
        author = "Elastic Security"
        id = "889b1248-a694-4c9b-8792-c04e582e814c"
        fingerprint = "a5e0c2bbd6a297c01f31eccabcbe356730f50f074587f679da6caeca99e54bc1"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BELARUS-VIRUS-MAKER" ascii fullword
        $a2 = "C:\\windows\\temp\\" ascii fullword
        $a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
        $a4 = "untInfector" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Generic_02a87a20 {
    meta:
        author = "Elastic Security"
        id = "02a87a20-a5b4-44c6-addc-c70b327d7b2c"
        fingerprint = "fb25a522888efa729ee6d43a3eec7ade3d08dba394f3592d1c3382a5f7a813c8"
        creation_date = "2022-03-04"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }
    condition:
        all of them
}

rule Windows_Trojan_Generic_4fbff084 {
    meta:
        author = "Elastic Security"
        id = "4fbff084-5280-4ff8-9c21-c437207231a5"
        fingerprint = "728d7877e7a16fbb756b1c3b6c90ff3b718f0f750803b6a1549cb32c69be0dfc"
        creation_date = "2023-02-28"
        last_modified = "2023-04-23"
        description = "Shellcode found in REF2924, belonging to for now unknown trojan"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "7010a69ba77e65e70f4f3f4a10af804e6932c2218ff4abd5f81240026822b401"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $string_decryption = { 8A 44 30 ?? 8A CD 88 45 ?? 32 C5 C0 C1 ?? 88 04 3E 0F B6 C5 0F B6 D9 0F AF D8 0F B6 C1 0F B6 D1 88 6D ?? 0F AF D0 0F B6 C5 0F B6 CD 0F AF C8 8A 6D ?? 8A 45 ?? C0 CB ?? 02 D1 32 DA 02 EB 88 6D ?? 38 45 ?? 74 ?? 8B 45 ?? 46 81 FE ?? ?? ?? ?? 7C ?? }
        $thread_start = { E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? BB ?? ?? ?? ?? 50 6A ?? 5A 8B CF 89 5C 24 ?? E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? }
        $resolve = { 8B 7A ?? 8D 5D ?? 85 FF 74 ?? 0F B7 0F 8D 7F ?? 8D 41 ?? 83 F8 ?? 77 ?? 83 C1 ?? 0F B7 33 83 C3 ?? 8D 46 ?? 83 F8 ?? 77 ?? 83 C6 ?? 85 C9 }
    condition:
        2 of them
}

rule Windows_Trojan_Generic_73ed7375 {
    meta:
        author = "Elastic Security"
        id = "73ed7375-c8ab-4d95-ae66-62b1b02a3d1e"
        fingerprint = "a026cc2db3bfebca4b4ea6e9dc41c2b18d0db730754ef3131d812d7ef9cd17d6"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2b17328a3ef0e389419c9c86f81db4118cf79640799e5c6fdc97de0fc65ad556"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 03 48 8B CE 49 8D 54 04 02 41 FF D6 48 89 03 48 83 C3 08 48 }
        $a2 = { 41 3C 42 8B BC 08 88 00 00 00 46 8B 54 0F 20 42 8B 5C 0F 24 4D }
    condition:
        all of them
}

rule Windows_Trojan_Generic_96cdf3c4 {
    meta:
        author = "Elastic Security"
        id = "96cdf3c4-6f40-4eb3-8bfd-b3c41422388a"
        fingerprint = "1037576e2c819031d5dc8067650c6b869e4d352ab7553fb5676a358059b37943"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9a4d68de36f1706a3083de7eb41f839d8c7a4b8b585cc767353df12866a48c81"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 74 24 28 48 8B 46 10 48 8B 4E 18 E8 9A CA F8 FF 84 C0 74 27 48 8B 54 }
        $a2 = { F2 74 28 48 89 54 24 18 48 89 D9 48 89 D3 E8 55 40 FF FF 84 C0 }
    condition:
        all of them
}

rule Windows_Trojan_Generic_f0c79978 {
    meta:
        author = "Elastic Security"
        id = "f0c79978-2df9-4ae2-bc5d-b5366acff41b"
        fingerprint = "94b2a5784ae843b831f9ce34e986b2687ded5c754edf44ff20490b851e0261fc"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "8f800b35bfbc8474f64b76199b846fe56b24a3ffd8c7529b92ff98a450d3bd38"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\IronPython."
        $a2 = "\\helpers\\execassembly_x64"
    condition:
        all of them
}

rule Windows_Trojan_Generic_40899c85 {
    meta:
        author = "Elastic Security"
        id = "40899c85-bb49-412c-8081-3a1359957c52"
        fingerprint = "d02a17a3b9efc2fd991320a5db7ab2384f573002157cddcd12becf137e893bd8"
        creation_date = "2023-12-15"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "88eb4f2e7085947bfbd03c69573fdca0de4a74bab844f09ecfcf88e358af20cc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "_sqlDataTypeSize"
        $a2 = "ChromeGetName"
        $a3 = "get_os_crypt"
    condition:
        all of them
}

rule Windows_Trojan_Generic_9997489c {
    meta:
        author = "Elastic Security"
        id = "9997489c-4e22-4df1-90cb-dd098ca26505"
        fingerprint = "4c872be4e5eaf46c92e6f7d62ed0801992c36fee04ada1a1a3039890e2893d8c"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $ldrload_dll = { 43 6A 45 9E }
        $loadlibraryw = { F1 2F 07 B7 }
        $ntallocatevirtualmemory = { EC B8 83 F7 }
        $ntcreatethreadex = { B0 CF 18 AF }
        $ntqueryinformationprocess = { C2 5D DC 8C }
        $ntprotectvirtualmemory = { 88 28 E9 50 }
        $ntreadvirtualmemory = { 03 81 28 A3 }
        $ntwritevirtualmemory = { 92 01 17 C3 }
        $rtladdvectoredexceptionhandler = { 89 6C F0 2D }
        $rtlallocateheap = { 5A 4C E9 3B }
        $rtlqueueworkitem = { 8E 02 92 AE }
        $virtualprotect = { 0D 50 57 E8 }
    condition:
        4 of them
}

rule Windows_Trojan_Generic_2993e5a5 {
    meta:
        author = "Elastic Security"
        id = "2993e5a5-26b2-4cfd-8130-4779abcfecb2"
        fingerprint = "709015984e3c9abaf141b76bf574921466493475182ca30a56dbc3671030b632"
        creation_date = "2024-03-18"
        last_modified = "2024-03-18"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9f9b926cef69e879462d9fa914dda8c60a01f3d409b55afb68c3fb94bf1a339b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }
    condition:
        1 of them
}

rule Windows_Trojan_Generic_0e135d58 {
    meta:
        author = "Elastic Security"
        id = "0e135d58-efd9-4d5e-95d8-ddd597f8e6a8"
        fingerprint = "e1a9e0c4e5531ae4dd2962285789c3bb8bb2621aa20437384fc3abcc349718c6"
        creation_date = "2024-03-19"
        last_modified = "2024-03-19"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }
    condition:
        1 of them
}

rule Windows_Trojan_Generic_9e4bb0ce {
    meta:
        author = "Elastic Security"
        id = "9e4bb0ce-b1ed-45dc-8d86-943eb76f0bb4"
        fingerprint = "4fb0eafc58972ef6fef87a88e43ae320420d760f545a66aab28dc3a65f629631"
        creation_date = "2025-10-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2d93a17f04bf2fcd51c2142043af3840895ae7ba43909a26420c4879d214a3c3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PluginMe" ascii fullword
        $a2 = "\\cmd.exe -Puppet" ascii fullword
        $a3 = "ERROR 1" ascii fullword
        $a4 = "ERROR 2" ascii fullword
        $a5 = "AYAgent.aye" ascii fullword
        $a6 = "mssecess.exe" ascii fullword
        $a7 = "shell\\open\\command" ascii fullword
        $a8 = "WinSta0\\Default" ascii fullword
        $a9 = { C6 44 24 ?? 53 C6 44 24 ?? 74 C6 44 24 ?? 61 C6 44 24 ?? 30 C6 44 24 ?? 5C }
        $a10 = { C6 44 24 ?? 41 C6 44 24 ?? 6C C6 44 24 ?? 69 C6 44 24 ?? 63 C6 44 24 ?? 61 C6 44 24 ?? 74 C6 44 24 ?? 69 }
        $a11 = { C6 44 24 ?? 2F C6 44 24 ?? 34 C6 44 24 ?? 2E C6 44 24 ?? 30 C6 44 24 ?? 20 C6 44 24 ?? 28 C6 44 24 ?? 63 }
        $a12 = "%c%c%c%c%c%c" ascii fullword
        $a13 = { 25 2D 32 34 73 20 25 2D 31 35 00 }
    condition:
        5 of them
}

rule Windows_Trojan_Generic_41da339f {
    meta:
        author = "Elastic Security"
        id = "41da339f-0266-4e8e-bae6-9b4c58210856"
        fingerprint = "6c6d63d9595bc37714bf33ccda155825c507f566b1654182a85e86e0e3bffb49"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2340f152e8cb4cc7d5d15f384517d756a098283aef239f8cbfe3d91f8722800a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = { 43 3A 5C 55 73 65 72 73 5C 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 5C 44 65 73 6B 74 6F 70 5C E6 9B BF E6 8D A2 E9 85 8D E7 BD AE E6 96 87 E4 BB B6 5C 77 33 77 70 2D 73 76 63 68 6F 73 74 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 43 62 73 4D 73 67 41 70 69 2E 70 64 62 }
        $str1 = "C:\\Windows\\System32\\drivers\\WUDFPfprot.sys" fullword
        $str2 = "C:\\Windows\\System32\\drivers\\WppRecorderpo.sys" fullword
        $str3 = "C:\\Windows\\System32\\drivers\\WppRecorderrt.sys" fullword
        $str4 = "WsmRes64.dll" fullword
        $str5 = "CbsMsgApi.dll" fullword
    condition:
        $pdb or 4 of ($str*)
}

rule Windows_Trojan_Generic_4a773368 {
    meta:
        author = "Elastic Security"
        id = "4a773368-deaf-4248-b0ec-c4e924cc7428"
        fingerprint = "96329cbe576ba9772259c068916b928e7c33afcd18616ddd04d82227459d6a7f"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "055bdcaa0b69a1e205c931547ef863531e9fdfdaac93aaea29fb701c7b468294"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = { 43 3A 5C 55 73 65 72 73 5C 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 5C 44 65 73 6B 74 6F 70 5C E6 9B BF E6 8D A2 E9 85 8D E7 BD AE E6 96 87 E4 BB B6 5C 77 33 77 70 73 65 72 76 69 63 65 2D 73 76 63 68 6F 73 74 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 43 62 73 4D 73 67 41 70 69 2E 70 64 62 }
        $str1 = "AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD" wide fullword
        $str2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide fullword
        $str3 = "ExcuteEnLargeDll failed with error code " fullword
        $str4 = "ChangeServiceConfig2 (SERVICE_CONFIG_DESCRIPTION) failed with error code" fullword
    condition:
        $pdb or 3 of ($str*)
}

