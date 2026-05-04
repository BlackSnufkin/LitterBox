rule MacOS_Trojan_Metasploit_6cab0ec0 {
    meta:
        author = "Elastic Security"
        id = "6cab0ec0-0ac5-4f43-8a10-1f46822a152b"
        fingerprint = "e13c605d8f16b2b2e65c717a4716c25b3adaec069926385aff88b37e3db6e767"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = "mettlesploit! " ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_293bfea9 {
    meta:
        author = "Elastic Security"
        id = "293bfea9-c5cf-4711-bec0-17a02ddae6f2"
        fingerprint = "d47e8083268190465124585412aaa2b30da126083f26f3eda4620682afd1d66e"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "_webcam_get_frame" ascii fullword
        $a2 = "_get_process_info" ascii fullword
        $a3 = "process_new: got %zd byte executable to run in memory" ascii fullword
        $a4 = "Dumping cert info:" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_448fa81d {
    meta:
        author = "Elastic Security"
        id = "448fa81d-14c7-479b-8d1e-c245ee261ef6"
        fingerprint = "ff040211f664f3f35cd4f4da0e5eb607ae3e490aae75ee97a8fb3cb0b08ecc1f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "7ab5490dca314b442181f9a603252ad7985b719c8aa35ddb4c3aa4b26dcc8a42"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "/Users/vagrant/mettle/mettle/src/process.c" ascii fullword
        $a2 = "/Users/vagrant/mettle/mettle/src/c2_http.c" ascii fullword
        $a3 = "/Users/vagrant/mettle/mettle/src/mettle.c" ascii fullword
    condition:
        any of them
}

rule MacOS_Trojan_Metasploit_768df39d {
    meta:
        author = "Elastic Security"
        id = "768df39d-7ee9-454e-82f8-5c7bd733c61a"
        fingerprint = "d45230c1111bda417228e193c8657d2318b1d2cddfbd01c5c6f2ea1d0be27a46"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_7ce0b709 {
    meta:
        author = "Elastic Security"
        id = "7ce0b709-1d96-407c-8eca-6af64e5bdeef"
        fingerprint = "3eb7f78d2671e16c16a6d9783995ebb32e748612d32ed4f2442e9f9c1efc1698"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_f11ccdac {
    meta:
        author = "Elastic Security"
        id = "f11ccdac-be75-4ba8-800a-179297a40792"
        fingerprint = "fbc1a5b77ed485706ae38f996cd086253ea1d43d963cb497446e5b0f3d0f3f11"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit shell_find_port.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_d9b16f4c {
    meta:
        author = "Elastic Security"
        id = "d9b16f4c-8cc9-42ce-95fa-8db06df9d582"
        fingerprint = "cf5cfc372008ae98a0958722a7b23f576d6be3b5b07214d21594a48a87d92fca"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_2992b917 {
    meta:
        author = "Elastic Security"
        id = "2992b917-32bd-4fd8-8221-0d061239673d"
        fingerprint = "055129bc7931d0334928be00134c109ab36825997b2877958e0ca9006b55575e"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_27d409f1 {
    meta:
        author = "Elastic Security"
        id = "27d409f1-80fd-4d07-815a-4741c48e0bf6"
        fingerprint = "43be41784449fc414c3e3bc7f4ca5827190fa10ac4cdd8500517e2aa6cce2a56"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_65a2394b {
    meta:
        author = "Elastic Security"
        id = "65a2394b-0e66-4cb5-b6aa-3909120f0a94"
        fingerprint = "082da76eb8da9315d495b79466366367f19170f93c0a29966858cb92145e38d7"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stages vforkshell.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_c7b7a90b {
    meta:
        author = "Elastic Security"
        id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
        fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_4bd6aaca {
    meta:
        author = "Elastic Security"
        id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
        fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
        threat_name = "MacOS.Trojan.Metasploit"
        reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }
    condition:
        all of them
}

rule MacOS_Trojan_Metasploit_5e5b685f {
    meta:
        author = "Elastic Security"
        id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
        fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Metasploit"
        reference_sample = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }
    condition:
        all of them
}

