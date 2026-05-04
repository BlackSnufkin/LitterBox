rule Linux_Backdoor_Generic_babf9101 {
    meta:
        author = "Elastic Security"
        id = "babf9101-1e6e-4268-a530-e99e2c905b0d"
        fingerprint = "a578b052910962523f26f14f0d0494481fe0777c01d9f6816c7ab53083a47adc"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "9ea73d2c2a5f480ae343846e2b6dd791937577cb2b3d8358f5b6ede8f3696b86"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C4 10 89 45 F4 83 7D F4 00 79 1F 83 EC 0C 68 22 }
    condition:
        all of them
}

rule Linux_Backdoor_Generic_5776ae49 {
    meta:
        author = "Elastic Security"
        id = "5776ae49-64e9-46a0-a0bb-b0226eb9a8bd"
        fingerprint = "2d36fbe1820805c8fd41b2b34a2a2b950fc003ae4f177042dc0d2568925c5b76"
        creation_date = "2021-04-06"
        last_modified = "2022-01-26"
        threat_name = "Linux.Backdoor.Generic"
        reference_sample = "e247a5decb5184fd5dee0d209018e402c053f4a950dae23be59b71c082eb910c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 18 C1 E8 08 88 47 12 8B 46 18 88 47 13 83 C4 1C 5B 5E 5F 5D }
    condition:
        all of them
}

