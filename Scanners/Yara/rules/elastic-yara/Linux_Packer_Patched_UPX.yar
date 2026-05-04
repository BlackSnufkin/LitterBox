rule Linux_Packer_Patched_UPX_62e11c64 {
    meta:
        author = "Elastic Security"
        id = "62e11c64-fc7d-4a0a-9d72-ad53ec3987ff"
        fingerprint = "3297b5c63e70c557e71b739428b453039b142e1e04c2ab15eea4627d023b686d"
        creation_date = "2021-06-08"
        last_modified = "2021-07-28"
        threat_name = "Linux.Packer.Patched_UPX"
        reference = "https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/"
        reference_sample = "02f81a1e1edcb9032a1d7256a002b11e1e864b2e9989f5d24ea1c9b507895669"
        severity = 60
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 55 50 58 21 [4] 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        all of them and $a in (0 .. 255)
}

