rule MacOS_Cryptominer_Generic_d3f68e29 {
    meta:
        author = "Elastic Security"
        id = "d3f68e29-830d-4d40-a285-ac29aed732fa"
        fingerprint = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
        $a2 = "Ethminer - GPU ethash miner" ascii fullword
        $a3 = "StratumClient"
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_365ecbb9 {
    meta:
        author = "Elastic Security"
        id = "365ecbb9-586e-4962-a5a8-05e871f54eff"
        fingerprint = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }
    condition:
        all of them
}

rule MacOS_Cryptominer_Generic_4e7d4488 {
    meta:
        author = "Elastic Security"
        id = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
        fingerprint = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Generic"
        reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }
    condition:
        all of them
}

