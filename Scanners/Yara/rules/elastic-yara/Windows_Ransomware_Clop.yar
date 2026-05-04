rule Windows_Ransomware_Clop_6a1670aa : beta {
    meta:
        author = "Elastic Security"
        id = "6a1670aa-7f78-455b-9e28-f39ed4c6476e"
        fingerprint = "7c24cc6a519922635a519dad412d1a07728317b91f90a120ccc1c7e7e2c8a002"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies CLOP ransomware in unpacked state"
        threat_name = "Windows.Ransomware.Clop"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = { FF 15 04 E1 40 00 83 F8 03 74 0A 83 F8 02 }
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Clop_e04959b5 : beta {
    meta:
        author = "Elastic Security"
        id = "e04959b5-f3da-428d-8b56-8a9817fdebe0"
        fingerprint = "7367b90772ce6db0d639835a0a54a994ef8ed351b6dadff42517ed5fbc3d0d1a"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies CLOP ransomware in unpacked state"
        threat_name = "Windows.Ransomware.Clop"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "-%s\\CIopReadMe.txt" wide fullword
        $a2 = "CIopReadMe.txt" wide fullword
        $a3 = "%s-CIop^_" wide fullword
        $a4 = "%s%s.CIop" wide fullword
        $a5 = "BestChangeT0p^_-666" ascii fullword
        $a6 = ".CIop" wide fullword
        $a7 = "A%s\\ClopReadMe.txt" wide fullword
        $a8 = "%s%s.Clop" wide fullword
        $a9 = "CLOP#666" wide fullword
        $a10 = "MoneyP#666" wide fullword
    condition:
        1 of ($a*)
}

rule Windows_Ransomware_Clop_9ac9ea3e : beta {
    meta:
        author = "Elastic Security"
        id = "9ac9ea3e-72e1-4151-a2f8-87869f5f98e3"
        fingerprint = "1cb0adb36e94ef8f8d74862250205436ed3694ed7719d8e639cfdd0c8632fd6c"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies CLOP ransomware in unpacked state"
        threat_name = "Windows.Ransomware.Clop"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = { 8B 1D D8 E0 40 00 33 F6 8B 3D BC E0 40 00 }
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Clop_606020e7 : beta {
    meta:
        author = "Elastic Security"
        id = "606020e7-ce1a-4a48-b801-100fd22b3791"
        fingerprint = "5ec4e00ddf2cb1315ec7d62dd228eee0d9c15fafe4712933d42e868f83f13569"
        creation_date = "2020-05-03"
        last_modified = "2021-08-23"
        description = "Identifies CLOP ransomware in unpacked state"
        threat_name = "Windows.Ransomware.Clop"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { B8 E1 83 0F 3E F7 E6 8B C6 C1 EA 04 8B CA C1 E1 05 03 CA }
    condition:
        1 of ($d*)
}

