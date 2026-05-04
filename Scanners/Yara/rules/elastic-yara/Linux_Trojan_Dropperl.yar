rule Linux_Trojan_Dropperl_b97baf37 {
    meta:
        author = "Elastic Security"
        id = "b97baf37-48db-4eb7-85c7-08e75054bea7"
        fingerprint = "0852f1afa6162d14b076a3fc1f56e4d365b5d0e8932bae6ab055000cca7d1fba"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 12 48 89 10 83 45 DC 01 83 45 D8 01 8B 45 D8 3B 45 BC 7C CF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_e2443be5 {
    meta:
        author = "Elastic Security"
        id = "e2443be5-da15-4af2-b090-bf5accf2a844"
        fingerprint = "e49acaa476bd669b40ccc82a7d3a01e9c421e6709ecbfe8d0e24219677c96339"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F0 75 DB EB 17 48 8B 45 F8 48 83 C0 08 48 8B 10 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_683c2ba1 {
    meta:
        author = "Elastic Security"
        id = "683c2ba1-fe4a-44e4-b176-8d5d5788e1a4"
        fingerprint = "42dcea472417140d0f7768e8189ac3a8a46aaeff039be1efd36f8d50f81e347c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "a02e166fbf002dd4217c012f24bb3a8dbe310a9f0b0635eb20a7d315049367e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_8bca73f6 {
    meta:
        author = "Elastic Security"
        id = "8bca73f6-c3ec-45a3-a5ae-67c871aaf9df"
        fingerprint = "36df2fd9746da80697ef675f84f47efb3cb90e9757677e4f565a7576966eb169"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "e7c17b7916b38494b9a07c249acb99499808959ba67125c29afec194ca4ae36c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 62 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_c4018572 {
    meta:
        author = "Elastic Security"
        id = "c4018572-a8af-4204-bc19-284a2a27dfdd"
        fingerprint = "f2ede50ea639af593211c9ef03ee2847a32cf3eb155db4e2ca302f3508bf2a45"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c1515b3a7a91650948af7577b613ee019166f116729b7ff6309b218047141f6d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 97 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_733c0330 {
    meta:
        author = "Elastic Security"
        id = "733c0330-3163-48f3-a780-49be80a3387f"
        fingerprint = "ee233c875dd3879b4973953a1f2074cd77abf86382019eeb72da069e1fd03e1c"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "b303f241a2687dba8d7b4987b7a46b5569bd2272e2da3e0c5e597b342d4561b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 A0 FB FF FF 83 7D DC 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_39f4cd0d {
    meta:
        author = "Elastic Security"
        id = "39f4cd0d-4261-4d62-a527-f403edadbd0c"
        fingerprint = "e1cdd678a1f46a3c6d26d53dd96ba6c6a45f97e743765c534f644af7c6450f8e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c08e1347877dc77ad73c1e017f928c69c8c78a0e3c16ac5455668d2ad22500f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 ?? FA FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

