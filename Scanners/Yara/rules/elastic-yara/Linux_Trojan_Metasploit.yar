rule Linux_Trojan_Metasploit_69e20012 {
    meta:
        author = "Elastic Security"
        id = "69e20012-4f5d-42ce-9913-8bf793d2a695"
        fingerprint = "263efec478e54c025ed35bba18a0678ceba36c90f42ccca825f2ba1202e58248"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "debb5d12c1b876f47a0057aad19b897c21f17de7b02c0e42f4cce478970f0120"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mmap = { 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 48 85 C0 78 }
        $socket = { 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E [0-6] 0F 05 48 85 C0 78 }
        $connect = { 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 }
        $failure_handler = { 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 }
        $exit = { 6A 3C 58 6A 01 5F 0F 05 }
        $receive = { 5A 0F 05 48 85 C0 78 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_0c629849 {
    meta:
        author = "Elastic Security"
        id = "0c629849-8127-4fec-a225-da29bf41435e"
        fingerprint = "3e98ffa46e438421056bf4424382baa6fbe30e5fc16dbd227bceb834873dbe41"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "ad070542729f3c80d6a981b351095ab8ac836b89a5c788dff367760a2d8b1dbb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $socket_call = { 6A 29 58 6A 0A 5F 6A 01 5E 31 D2 0F 05 50 5F }
        $populate_sockaddr_in6 = { 99 52 52 52 66 68 }
        $calls = { 6A 31 58 6A 1C 5A 0F 05 6A 32 58 6A 01 5E 0F 05 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 }
        $dup2 = { 48 97 6A 03 5E 6A 21 58 FF CE 0F 05 E0 F7 }
        $exec_call = { 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 54 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_849cc5d5 {
    meta:
        author = "Elastic Security"
        id = "849cc5d5-737a-4ea4-9bb6-cec26b132ff2"
        fingerprint = "859638998983b9dc0cffc204985b2c4db8a4fb2a97ff4e791fd6762ff6b1f5da"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "42d734dbd33295bd68e5a545a29303a2104a5a92e5fee31d645e2a6410cc03e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $init1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $init2 = { 6A 10 5A 6A ?? 58 0F }
        $shell1 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
        $shell2 = { 48 96 6A 2B 58 0F 05 50 56 5F 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 97 5F 0F 05 FF E6 }
    condition:
        all of ($init*) and 1 of ($shell*)
}

rule Linux_Trojan_Metasploit_da378432 {
    meta:
        author = "Elastic Security"
        id = "da378432-d549-4ba8-9e33-a0d0656fc032"
        fingerprint = "db6e226c18211d845c3495bb39472646e64842d4e4dd02d9aad29178fd22ea95"
        creation_date = "2024-05-03"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "277499da700e0dbe27269c7cfb1fc385313c4483912a9a3f0c15adba33ecd0bf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 97 }
        $str2 = { 6A 10 5A 6A ?? 58 0F }
        $str3 = { 6A 03 5E 48 FF CE 6A 21 58 0F 05 75 F6 6A 3B 58 99 48 BB 2F 62 69 6E 2F 73 68 00 53 48 89 E7 52 57 48 89 E6 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_b957e45d {
    meta:
        author = "Elastic Security"
        id = "b957e45d-0eb6-4580-af84-98608bbc34ef"
        fingerprint = "ac71352e2b4c8ee8917b1469cd33e6b54eb4cdcd96f02414465127c5cad6b710"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom nonx TCP reverse shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "78af84bad4934283024f4bf72dfbf9cc081d2b92a9de32cc36e1289131c783ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 89 E1 CD 80 97 5B }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 57 89 E1 43 CD 80 5B 99 B6 0C B0 03 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_1a98f2e2 {
    meta:
        author = "Elastic Security"
        id = "1a98f2e2-9354-4d04-b1c0-d3998e54e2c4"
        fingerprint = "b9865aad13b4d837e7541fe6a501405aa7d694c8fefd96633c0239031ebec17a"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom nonx TCP bind shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "89be4507c9c24c4ec9a7282f197a9a6819e696d2832df81f7e544095d048fc22"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 02 6A 66 58 99 89 E1 CD 80 96 43 52 }
        $str2 = { 66 53 89 E1 6A 66 58 50 51 56 89 E1 CD 80 B0 66 D1 E3 CD 80 52 52 56 43 89 E1 B0 66 CD 80 93 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_d74153f6 {
    meta:
        author = "Elastic Security"
        id = "d74153f6-0047-4576-8c3e-db0525bb3a92"
        fingerprint = "824baa1ee7fda8074d76e167d3c5cc1911c7224bb72b1add5e360f26689b48c2"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom IPv6 TCP reverse shells"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2823d27492e2e7a95b67a08cb269eb6f4175451d58b098ae429330913397d40a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 43 53 6A 0A 89 E1 6A 66 58 CD 80 96 99 }
        $str2 = { 89 E1 6A 1C 51 56 89 E1 43 43 6A 66 58 CD 80 89 F3 B6 0C B0 03 CD 80 89 DF }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_f7a31e87 {
    meta:
        author = "Elastic Security"
        id = "f7a31e87-c3d7-4a26-9879-68893780283e"
        fingerprint = "7171cb9989405be295479275d8824ced7e3616097db88e3b0f8f1ef6798607e2"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom shell find tag payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "82b55d8c0f0175d02399aaf88ad9e92e2e37ef27d52c7f71271f3516ba884847"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $setup = { 31 DB 53 89 E6 6A 40 B7 0A 53 56 53 89 E1 86 FB 66 FF 01 6A 66 58 CD 80 81 3E }
        $payload1 = { 5F FC AD FF }
        $payload2 = { 5F 89 FB 6A 02 59 6A 3F 58 CD 80 49 79 ?? 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 53 89 E1 CD 80 }
    condition:
        $setup and 1 of ($payload*)
}

rule Linux_Trojan_Metasploit_b0d2d4a4 {
    meta:
        author = "Elastic Security"
        id = "b0d2d4a4-4fd6-4fc0-959b-89d6969215ed"
        fingerprint = "f6d2e001d8cfb6f086327ddb457a964932a8200ff60ea973b26ac9fb909b4a9c"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom shell find port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a37c888875e84069763303476f0df6769df6015b33aded59fc1e23eb604f2163"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB 53 89 E7 6A 10 54 57 53 89 E1 B3 07 FF 01 6A 66 58 CD 80 }
        $str2 = { 5B 6A 02 59 B0 3F CD 80 49 }
        $str3 = { 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 99 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_5d26689f {
    meta:
        author = "Elastic Security"
        id = "5d26689f-3d3a-41f1-ac32-161b3b312b74"
        fingerprint = "b78fda9794dc24507405fc04bdc0a3e8abfcdc5c757787b7d9822f4ea2190120"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "dafefb4d79d848384442a697b1316d93fef2741fca854be744896ce1d7f82073"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $tiny_bind = { 31 D2 52 68 2F 2F 73 68 68 2F 62 69 6E 68 2D 6C 65 2F 89 E7 52 68 2F 2F 6E 63 68 2F 62 69 6E 89 E3 52 57 53 89 E1 31 C0 B0 0B CD 80 }
        $reg_bind_setup = { 31 DB F7 E3 B0 66 43 52 53 6A 02 89 E1 CD 80 52 50 89 E1 B0 66 B3 04 CD 80 B0 66 43 CD 80 59 93 }
        $reg_bind_dup_loop = { 6A 3F 58 CD 80 49 79 }
        $reg_bind_execve = { B0 0B 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 41 CD 80 }
    condition:
        ($tiny_bind) or (all of ($reg_bind*))
}

rule Linux_Trojan_Metasploit_1c8c98ae {
    meta:
        author = "Elastic Security"
        id = "1c8c98ae-46c8-45fe-ab42-7b053f0357ed"
        fingerprint = "a3b592cc6d9b00f76a1084c7c124cc199149ada5b8dc206cff3133718f045c9d"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom add user payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "1a2c40531584ed485f3ff532f4269241a76ff171956d03e4f0d3f9c950f186d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 C9 89 CB 6A 46 58 CD 80 6A 05 58 31 C9 51 68 73 73 77 64 68 2F 2F 70 61 68 2F 65 74 63 89 E3 41 B5 04 CD 80 93 }
        $str2 = { 59 8B 51 FC 6A 04 58 CD 80 6A 01 58 CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_47f4b334 {
    meta:
        author = "Elastic Security"
        id = "47f4b334-619b-4b9c-841d-b00c09dd98e5"
        fingerprint = "955d65f1097ec9183db8bd3da43090f579a27461ba345bb74f62426734731184"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "c3821f63a7ec8861a6168b4bb494bf8cbac436b3abf5eaffbc6907fd68ebedb8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 31 C9 F7 E1 B0 0B [0-1] 68 2F ?? ?? ?? 68 2F 62 69 6E 89 E3 CD 80 }
        $payload2a = { 31 DB F7 E3 B0 0B 52 }
        $payload2b = { 88 14 1E 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 52 56 57 53 89 E1 CD 80 }
        $payload3a = { 6A 0B 58 99 52 }
        $payload3b = { 89 E7 68 2F 73 68 00 68 2F 62 69 6E 89 E3 52 E8 }
        $payload3c = { 57 53 89 E1 CD 80 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_0b014e0e {
    meta:
        author = "Elastic Security"
        id = "0b014e0e-3f5a-4dcc-8860-eb101281b8a5"
        fingerprint = "7a61a0e169bf6aa8760b42c5b260dee453ea6a85fe9e5da46fb7598994904747"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom exec payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "a24443331508cc72b3391353f91cd009cafcc223ac5939eab12faf57447e3162"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $payload1 = { 48 B8 2F [0-1] 62 69 6E 2F 73 68 ?? ?? 50 54 5F 52 5E 6A 3B 58 0F 05 }
        $payload2a = { 48 B8 2F 2F 62 69 6E 2F 73 68 99 EB ?? 5D 52 5B }
        $payload2b = { 54 5E 52 50 54 5F 52 55 56 57 54 5E 6A 3B 58 0F 05 }
        $payload3a = { 48 B8 2F 62 69 6E 2F 73 68 00 99 50 54 5F 52 }
        $payload3b = { 54 5E 52 E8 }
        $payload3c = { 56 57 54 5E 6A 3B 58 0F 05 }
    condition:
        $payload1 or (all of ($payload2*)) or (all of ($payload3*))
}

rule Linux_Trojan_Metasploit_ccc99be1 {
    meta:
        author = "Elastic Security"
        id = "ccc99be1-6ea9-4090-acba-3bbe82b127c1"
        fingerprint = "88e30402974b853e5f83a3033129d99e7dd1f6b31b5855b1602ef2659a0f7f56"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom pingback bind shell payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0e9f52d7aa6bff33bfbdba6513d402db3913d4036a5e1c1c83f4ccd5cc8107c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 56 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 }
        $str2 = { 51 48 89 E6 54 5E 6A 31 58 6A 10 5A 0F 05 6A 32 58 6A 01 5E 0F 05 }
        $str3 = { 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 48 97 }
        $str4 = { 5E 48 31 C0 48 FF C0 0F 05 6A 3C 58 6A 01 5F 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_ed4b2c85 {
    meta:
        author = "Elastic Security"
        id = "ed4b2c85-730f-4a77-97ed-5439a0493a4a"
        fingerprint = "c38513fa6b1ed23ec91ae316af9793c5c01ac94b43ba5502f9c32a0854aec96f"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom bind TCP random port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_2b0ad6f0 {
    meta:
        author = "Elastic Security"
        id = "2b0ad6f0-44d2-4e7e-8cca-2b0ae1b88d48"
        fingerprint = "b15da42f957107d54bfad78eff3a703cc2a54afcef8207d42292f2520690d585"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x64 msfvenom find TCP port payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
        $str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
        $str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_bf205d5a {
    meta:
        author = "Elastic Security"
        id = "bf205d5a-2bba-497a-8d40-58422e91fe45"
        fingerprint = "91ac22c6302de26717f0666c59fa3765144df2d22d0c3a311a106bc1d9d2ae70"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom bind IPv6 TCP shell payloads "
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "2162a89f70edd7a7f93f8972c6a13782fb466cdada41f255f0511730ec20d037"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 6A 7D 58 99 B2 07 B9 00 10 00 00 89 E3 66 81 E3 00 F0 CD 80 31 DB F7 E3 53 43 53 6A ?? 89 E1 B0 66 CD 80 }
        $str2 = { 51 6A 04 54 6A 02 6A 01 50 }
        $str3 = { 6A 0E 5B 6A 66 58 CD 80 89 F8 83 C4 14 59 5B 5E }
        $str4 = { CD 80 93 B6 0C B0 03 CD 80 87 DF 5B B0 06 CD 80 }
        $ipv6 = { 6A 02 5B 52 52 52 52 52 52 ?? ?? ?? ?? ?? 89 E1 6A 1C }
        $socket = { 51 50 89 E1 6A 66 58 CD 80 D1 E3 B0 66 CD 80 57 43 B0 66 89 51 04 CD 80 }
    condition:
        3 of ($str*) and $ipv6 and $socket
}

rule Linux_Trojan_Metasploit_e5b61173 {
    meta:
        author = "Elastic Security"
        id = "e5b61173-cf1c-4176-bc43-550c0213ce98"
        fingerprint = "7052cce595dbbf36aed5e1edab12a75f06059e6267c859516011d8feb9e328e6"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom stageless TCP reverse shell payload"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "8032a7a320102c8e038db16d51b8615ee49f04dab1444326463f75ce0c5947a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 93 59 B0 3F CD 80 49 79 }
        $str2 = { 89 E1 B0 66 50 51 53 B3 03 89 E1 CD 80 52 }
        $str3 = { 89 E3 52 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}

rule Linux_Trojan_Metasploit_dd5fd075 {
    meta:
        author = "Elastic Security"
        id = "dd5fd075-bd52-47a9-b737-e55ab10a071d"
        fingerprint = "df2a4f90ec3227555671136c18931118fc9df32340d87aeb3f3fa7fdf2ba6179"
        creation_date = "2024-05-07"
        last_modified = "2024-05-21"
        description = "Detects x86 msfvenom TCP bind shell payloads"
        threat_name = "Linux.Trojan.Metasploit"
        reference_sample = "b47132a92b66c32c88f39fe36d0287c6b864043273939116225235d4c5b4043a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = { 31 DB F7 E3 53 43 53 6A 02 89 E1 B0 66 CD 80 5B 5E 52 }
        $str2 = { 6A 10 51 50 89 E1 6A 66 58 CD 80 89 41 04 B3 04 B0 66 CD 80 43 B0 66 CD 80 93 59 }
        $str3 = { 6A 3F 58 CD 80 49 79 F8 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 B0 0B CD 80 }
    condition:
        all of them
}

