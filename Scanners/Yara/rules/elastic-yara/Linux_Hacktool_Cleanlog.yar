rule Linux_Hacktool_Cleanlog_c2907d77 {
    meta:
        author = "Elastic Security"
        id = "c2907d77-6ea9-493f-a7b3-4a0795da0a1d"
        fingerprint = "131c71086c30ab22ca16b3020470561fa3d32c7ece9a8faa399a733e8894da30"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "613ac236130ab1654f051d6f0661fa62414f3bef036ea4cc585b4b21a4bb9d2b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 10 89 7D FC 83 7D FC 00 7E 11 8B 45 FC BE 09 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_3eb725d1 {
    meta:
        author = "Elastic Security"
        id = "3eb725d1-24de-427a-b6ed-3ca03c0716df"
        fingerprint = "54d3c59ba5ca16fbe99a4629f4fe7464d13f781985a7f35d05604165f9284483"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E0 83 45 C0 01 EB 11 83 45 DC 01 EB 0B 83 45 D8 01 EB 05 83 45 }
    condition:
        all of them
}

rule Linux_Hacktool_Cleanlog_400b7595 {
    meta:
        author = "Elastic Security"
        id = "400b7595-c3c4-4999-b3b9-dcfe9b5df3f6"
        fingerprint = "4423f1597b199046bfc87923e3e229520daa2da68c4c4a3ac69127ace518f19a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Cleanlog"
        reference_sample = "4df4ebcc61ab2cdb8e5112eeb4e2f29e4e841048de43d7426b1ec11afe175bf6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 72 20 65 6E 74 72 79 20 28 64 65 66 61 75 6C 74 3A 20 31 73 74 20 }
    condition:
        all of them
}

