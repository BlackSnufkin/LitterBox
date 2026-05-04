rule Windows_Hacktool_COFFLoader_81ba13b8 {
    meta:
        author = "Elastic Security"
        id = "81ba13b8-8994-4fe9-98e5-44514c554e8b"
        fingerprint = "ef9f11d9cd6c3b46f7d13ea039dcad6fa24515495466b1102ec8c1c8bed8853e"
        creation_date = "2024-04-22"
        last_modified = "2024-05-08"
        threat_name = "Windows.Hacktool.COFFLoader"
        reference_sample = "c2e03659eb1594dc958e01344cfa9ba126d66736b089db5e3dd1b1c3e3e7d2f7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BeaconDataParse" ascii fullword
        $a2 = "BeaconDataInt" ascii fullword
        $a3 = "BeaconDataShort" ascii fullword
        $a4 = "BeaconDataLength" ascii fullword
        $a5 = "BeaconDataExtract" ascii fullword
        $a6 = "BeaconFormatAlloc" ascii fullword
        $a7 = "BeaconFormatReset" ascii fullword
        $a8 = "BeaconFormatFree" ascii fullword
        $a9 = "BeaconFormatAppend" ascii fullword
        $a10 = "BeaconFormatPrintf" ascii fullword
        $a11 = "BeaconFormatToString" ascii fullword
        $a12 = "BeaconFormatInt" ascii fullword
        $a13 = "BeaconPrintf" ascii fullword
        $a14 = "BeaconOutput" ascii fullword
        $a15 = "BeaconUseToken" ascii fullword
        $a16 = "BeaconRevertToken" ascii fullword
        $a17 = "BeaconDataParse" ascii fullword
        $a18 = "BeaconIsAdmin" ascii fullword
        $a19 = "BeaconGetSpawnTo" ascii fullword
        $a20 = "BeaconSpawnTemporaryProcess" ascii fullword
        $a21 = "BeaconInjectProcess" ascii fullword
        $a22 = "BeaconInjectTemporaryProcess" ascii fullword
        $a23 = "BeaconCleanupProcess" ascii fullword
        $b1 = "COFFLoader.x64.dll"
        $b2 = "COFFLoader.x86.dll"
    condition:
        5 of ($a*) or 1 of ($b*)
}

