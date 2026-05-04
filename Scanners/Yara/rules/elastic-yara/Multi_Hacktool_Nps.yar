rule Multi_Hacktool_Nps_c6eb4a27 {
    meta:
        author = "Elastic Security"
        id = "c6eb4a27-c481-41b4-914d-a27d10672d30"
        fingerprint = "1386e4cef0f347b38a4614311d585b0b83cb9526b19215392aee893e594950de"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Nps"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "4714e8ad9c625070ca0a151ffc98d87d8e5da7c8ef42037ca5f43baede6cfac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str_info0 = "Reconnecting..."
        $str_info1 = "Loading configuration file %s successfully"
        $str_info2 = "successful start-up of local socks5 monitoring, port"
        $str_info3 = "successful start-up of local tcp monitoring, port"
        $str_info4 = "start local file system, local path %s, strip prefix %s ,remote port %"
        $str_info5 = "start local file system, local path %s, strip prefix %s ,remote port %s"
    condition:
        all of them
}

rule Multi_Hacktool_Nps_f76f257d {
    meta:
        author = "Elastic Security"
        id = "f76f257d-0286-4b4d-9f73-2add23cfd07e"
        fingerprint = "4aaa270129ce0c8fdd40aae2ebc4f6595aec91cbfea9e0188542e9c3f38eedee"
        creation_date = "2024-01-24"
        last_modified = "2024-01-29"
        threat_name = "Multi.Hacktool.Nps"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        reference_sample = "80721b20a8667536a33fca50236f5c8e0c0d07aa7805b980e40818ab92cd9f4a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $string_decrypt_add = { 0F B6 BC 34 ?? ?? ?? ?? 44 0F B6 84 34 ?? ?? ?? ?? 44 01 C7 40 88 BC 34 ?? ?? ?? ?? 48 FF C6 }
        $string_decrypt_xor = { 0F B6 54 ?? ?? 0F B6 74 ?? ?? 31 D6 40 88 74 ?? ?? 48 FF C0 }
        $string_decrypt_sub = { 0F B6 94 04 ?? ?? ?? ?? 0F B6 B4 04 ?? ?? ?? ?? 29 D6 40 88 B4 04 ?? ?? ?? ?? 48 FF C0 }
        $NewJsonDb_str0 = { 63 6C 69 65 6E 74 73 2E 6A 73 6F 6E }
        $NewJsonDb_str1 = { 68 6F 73 74 73 2E 6A 73 6F 6E }
    condition:
        all of them
}

