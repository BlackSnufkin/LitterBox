rule Linux_Virus_Thebe_1eb5985a {
    meta:
        author = "Elastic Security"
        id = "1eb5985a-2b35-434f-81d9-f502dff25397"
        fingerprint = "5cf9aa9a31c36028025d5038c98d56aef32c9e8952aa5cd4152fbd811231769e"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Thebe"
        reference_sample = "30af289be070f4e0f8761f04fb44193a037ec1aab9cc029343a1a1f2a8d67670"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 42 31 C9 31 DB 31 F6 B0 1A CD 80 85 C0 0F 85 83 }
    condition:
        all of them
}

