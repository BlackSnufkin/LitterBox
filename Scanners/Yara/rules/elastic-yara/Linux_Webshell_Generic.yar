rule Linux_Webshell_Generic_e80ff633 {
    meta:
        author = "Elastic Security"
        id = "e80ff633-990e-4e2e-ac80-2e61685ab8b0"
        fingerprint = "dcca52dce2d50b0aa6cf0132348ce9dc234b985ae683b896d9971d409f109849"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Webshell.Generic"
        reference_sample = "7640ba6f2417931ef901044152d5bfe1b266219d13b5983d92ddbdf644de5818"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 A8 00 00 00 89 1C 24 83 3C 24 00 74 23 83 04 24 24 8D B4 24 AC 00 }
    condition:
        all of them
}

rule Linux_Webshell_Generic_41a5fa40 {
    meta:
        author = "Elastic Security"
        id = "41a5fa40-a4e7-4c97-a3b9-3700743265df"
        fingerprint = "49e0d55579453ec37c6757ddb16143d8e86ad7c7c4634487a1bd2215cd22df83"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Webshell.Generic"
        reference = "18ac7fbc3d8d3bb8581139a20a7fee8ea5b7fcfea4a9373e3d22c71bae3c9de0"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5A 46 55 6C 73 6E 55 6B 56 52 56 55 56 54 56 46 39 56 55 6B 6B }
    condition:
        all of them
}

