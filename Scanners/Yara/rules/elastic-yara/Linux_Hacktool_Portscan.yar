rule Linux_Hacktool_Portscan_a40c7ef0 {
    meta:
        author = "Elastic Security"
        id = "a40c7ef0-627c-4965-b4d3-b05b79586170"
        fingerprint = "bf686c3c313936a144265cbf75850c8aee3af3ae36cb571050c7fceed385451d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "c389c42bac5d4261dbca50c848f22c701df4c9a2c5877dc01e2eaa81300bdc29"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 54 50 44 00 52 65 73 70 6F 6E 73 65 20 77 61 73 20 4E 54 50 20 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_6c6000c2 {
    meta:
        author = "Elastic Security"
        id = "6c6000c2-7e9a-457c-a745-00a3ac83a4bc"
        fingerprint = "3c893aebe688d70aebcb15fdc0d2780d2ec0589084c915ff71519ec29e5017f1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "8877009fc8ee27ba3b35a7680b80d21c84ee7296bcabe1de51aeeafcc8978da7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 30 B9 0E 00 00 00 4C 89 D7 F3 A6 0F 97 C2 80 DA 00 84 D2 45 0F }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e191222d {
    meta:
        author = "Elastic Security"
        id = "e191222d-633a-4408-9a54-a70bb9e89cc0"
        fingerprint = "5580dd8b9180b8ff36c7d08a134b1b3782b41054d8b29b23fc5a79e7b0059fd1"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "e2f4313538c3ef23adbfc50f37451c318bfd1ffd0e5aaa346cce4cc37417f812"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 46 4F 55 4E 44 00 56 41 4C 55 45 00 44 45 4C 45 54 45 44 00 54 }
    condition:
        all of them
}

rule Linux_Hacktool_Portscan_e57b0a0c {
    meta:
        author = "Elastic Security"
        id = "e57b0a0c-66b8-488b-b19d-ae06623645fd"
        fingerprint = "829c7d271ae475ef06d583148bbdf91af67ce4c7a831da73cc52e8406e7e8f9e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Portscan"
        reference_sample = "f8ee385316b60ee551565876287c06d76ac5765f005ca584d1ca6da13a6eb619"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 83 7D 08 03 75 2B 83 EC 0C 8B 45 0C 83 C0 08 FF 30 8B 45 0C 83 }
    condition:
        all of them
}

