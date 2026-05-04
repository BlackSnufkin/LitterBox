rule Linux_Hacktool_Earthworm_4de7b584 {
    meta:
        author = "Elastic Security"
        id = "4de7b584-d25f-414b-bdd5-45f3672a62d8"
        fingerprint = "af2dc166ad5bbd3e312338a3932134c33c33c124551e7828eeef299d89419d21"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "9d61aabcf935121b4f7fc6b0d082d7d6c31cb43bf253a8603dd46435e66b7955"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 6F 63 6B 73 64 20 2C 20 72 63 73 6F 63 6B 73 20 2C 20 72 73 }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_82d5c4cf {
    meta:
        author = "Elastic Security"
        id = "82d5c4cf-ab96-4644-b1f3-2e95f1b49e7c"
        fingerprint = "400342ab702de1a7ec4dd7e9b415b8823512f74a9abe578f08f7d79265bef385"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 20 31 C0 89 C1 48 8D 55 F0 48 89 7D F8 48 8B }
    condition:
        all of them
}

rule Linux_Hacktool_Earthworm_4ec2ec63 {
    meta:
        author = "Elastic Security"
        id = "4ec2ec63-6b22-404f-a217-4e7d32bfbe9f"
        fingerprint = "1dfb594e369ca92a9e3f193499708c4992f6497ff1aa74ae0d6c2475a7e87641"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Earthworm"
        reference_sample = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 83 EC 20 BA 04 00 00 00 48 8D 45 F0 48 89 7D F8 89 }
    condition:
        all of them
}

