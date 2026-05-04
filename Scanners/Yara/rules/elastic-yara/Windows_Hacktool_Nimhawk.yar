rule Windows_Hacktool_Nimhawk_cdcc3540 {
    meta:
        author = "Elastic Security"
        id = "cdcc3540-1147-4ff8-bcd1-3d139332be42"
        fingerprint = "36d406ef96f5f315a368272310aae0c446d5e896436acfc1026825fbbd983d48"
        creation_date = "2025-04-25"
        last_modified = "2025-05-27"
        threat_name = "Windows.Hacktool.Nimhawk"
        reference_sample = "39381b1eeddcb05084480e3afe525d4c3c304c768a0c0da71118ff4cd6a4219c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "NimHawk"
        $s2 = "BeaconInjectTemporaryProcess"
        $s3 = "BeaconSpawnTemporaryProcess"
        $s4 = "getImplantIDFromRegistry"
    condition:
        all of them
}

