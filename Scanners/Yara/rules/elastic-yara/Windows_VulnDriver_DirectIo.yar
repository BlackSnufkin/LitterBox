rule Windows_VulnDriver_DirectIo_7bea6c8f {
    meta:
        author = "Elastic Security"
        id = "7bea6c8f-7006-4994-be21-614e3cf1ec76"
        fingerprint = "18a43821655a6d65242a8995b98bc7dc924a65ab7808ee09daf9a82f7794e906"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "1dadd707c55413a16320dc70d2ca7784b94c6658331a753b3424ae696c5d93ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DirectIo.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

rule Windows_VulnDriver_DirectIo_abe8bfa6 {
    meta:
        author = "Elastic Security"
        id = "abe8bfa6-0b51-4224-a7fc-4249e34ac0a2"
        fingerprint = "7fe138f9f951c00ae144029890fd228bf6f6a932c0d7e6cf6555ae10df92c725"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.DirectIo"
        reference_sample = "d84e3e250a86227c64a96f6d5ac2b447674ba93d399160850acb2339da43eae5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\DirectIo64.pdb"
        $str2 = { 9B 49 18 FC CD 5C EA D2 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1 and not $str2
}

