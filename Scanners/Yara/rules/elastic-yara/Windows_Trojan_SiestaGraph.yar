rule Windows_Trojan_SiestaGraph_8c36ddc1 {
    meta:
        author = "Elastic Security"
        id = "8c36ddc1-c7fa-4c25-a05c-59c29e4e7c31"
        fingerprint = "a76d2b45261da65215797a4792a3aae5051d88ba15d01b24487c83d6a38b9ff7"
        creation_date = "2022-12-14"
        last_modified = "2022-12-15"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        reference_sample = "50c2f1bb99d742d8ae0ad7c049362b0e62d2d219b610dcf25ba50c303ccfef54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "downloadAsync" ascii nocase fullword
        $a2 = "UploadxAsync" ascii nocase fullword
        $a3 = "GetAllDriveRootChildren" ascii fullword
        $a4 = "GetDriveRoot" ascii fullword
        $a5 = "sendsession" wide fullword
        $b1 = "ListDrives" wide fullword
        $b2 = "Del OK" wide fullword
        $b3 = "createEmailDraft" ascii fullword
        $b4 = "delMail" ascii fullword
    condition:
        all of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_SiestaGraph_ad3fe5c6 {
    meta:
        author = "Elastic Security"
        id = "ad3fe5c6-88ba-46cf-aefd-bd8ab0eff917"
        fingerprint = "653ca92d31c7212c1f154c2e18b3be095e9a39fe482ce99fbd84e19f4bf6ca64"
        creation_date = "2023-09-12"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GetAllDriveRootChildren" ascii fullword
        $a2 = "GetDriveRoot" ascii fullword
        $a3 = "sendsession" wide fullword
        $b1 = "status OK" wide fullword
        $b2 = "upload failed" wide fullword
        $b3 = "Failed to fetch file" wide fullword
        $c1 = "Specified file doesn't exist" wide fullword
        $c2 = "file does not exist" wide fullword
    condition:
        6 of them
}

rule Windows_Trojan_SiestaGraph_d801ce71 {
    meta:
        author = "Elastic Security"
        id = "d801ce71-2e3d-47bb-a194-c68b437d8ecc"
        fingerprint = "8e1d95313526650c2fa3dd00e779aec0e62d1a2273722ad913100eab003fc8b6"
        creation_date = "2023-09-12"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.SiestaGraph"
        reference = "https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry"
        reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $hashgenfunc = { 02 2C ?? 20 [4] 0A 16 0B 2B ?? 02 07 6F [4] 06 61 20 [4] 5A 0A 07 17 58 0B 07 02 6F [4] 32 ?? }
        $sendpostfunc = { 72 [4] 72 [4] 72 [4] 02 73 [4] 73 [4] 28 [4] 0A 72 [4] 72 [4] 06 28 [4] 2A }
        $command15 = { 25 16 1F 3A 9D 6F [4] 17 9A 13 ?? 11 ?? 28 [4] 13 ?? 11 ?? 28 [4] 11 ?? 28 [4] 2C 33 28 [4] 28 [4] 6F [4] 6F [4] 11 ?? 28 [4] 09 7B [4] 18 9A 72 [4] 72 [4] 28 [4] 26 DE }
    condition:
        all of them
}

