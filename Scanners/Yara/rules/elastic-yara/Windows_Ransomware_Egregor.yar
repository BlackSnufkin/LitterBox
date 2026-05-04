rule Windows_Ransomware_Egregor_f24023f3 : beta {
    meta:
        author = "Elastic Security"
        id = "f24023f3-c887-42fc-8927-cdbd04b5f84f"
        fingerprint = "3a82a548658e0823678ec9d633774018ddc6588f5e2fbce74826a46ce9c43c40"
        creation_date = "2020-10-15"
        last_modified = "2021-08-23"
        description = "Identifies EGREGOR (Sekhemt) ransomware"
        threat_name = "Windows.Ransomware.Egregor"
        reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "M:\\sc\\p\\testbuild.pdb" ascii fullword
        $a2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" wide fullword
        $a3 = "nIcG`]/h3kpJ0QEAC5OJC|<eT}}\\5K|h\\\\v<=lKfHKO~01=Lo0C03icERjo0J|/+|=P0<UeN|e2F@GpTe]|wpMP`AG+IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi/G"
        $a4 = "pVrGRgJui@6ejnOu@4KgacOarSh|firCToW1LoF]7BtmQ@2j|hup2owUHQ6W}\\U3gwV6OwSPTMQVq2|G=GKrHpjOqk~`Ba<qu\\2]r0RKkf/HGngsK7LhtvtJiR}+4J"
        $a5 = "Your network was ATTACKED, your computers and servers were LOCKED," ascii wide
        $a6 = "Do not redact this special technical block, we need this to authorize you." ascii wide
    condition:
        2 of ($a*)
}

rule Windows_Ransomware_Egregor_4ec2b90c : beta {
    meta:
        author = "Elastic Security"
        id = "4ec2b90c-b2de-463d-a9c6-478c255c2352"
        fingerprint = "6ae13632f50af11626250c30f570370da23deb265ff6c1fefd2e294c8c170998"
        creation_date = "2020-10-15"
        last_modified = "2021-08-23"
        description = "Identifies EGREGOR (Sekhemt) ransomware"
        threat_name = "Windows.Ransomware.Egregor"
        reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = { 18 F5 46 E0 5C 94 28 B3 5C 94 28 B3 5C 94 28 B3 E8 08 D9 B3 55 94 28 B3 E8 08 DB B3 29 94 28 B3 E8 08 DA B3 44 94 28 B3 67 CA 2B B2 4D 94 28 B3 67 CA 2D B2 47 94 28 B3 67 CA 2C B2 4C 94 28 B3 81 6B E3 B3 5F 94 28 B3 5C 94 29 B3 02 94 28 B3 5C 94 28 B3 5F 94 28 B3 CE CA 28 B2 5D 94 28 B3 CE CA 2A B2 5D 94 28 B3 }
        $b2 = { 34 4F 51 46 33 5C 45 6A 75 5E 7E 4E 37 53 49 7C 49 50 4B 32 73 43 47 5E 68 43 42 4E 7C 42 30 48 62 4C 34 6D 3C 2F 36 76 3D 43 5D 6B 4F 30 32 6E 60 35 68 40 33 60 4B 47 6F 33 55 36 71 56 4A 3D 40 5C 6A 69 4B 4A 60 5C 35 2B 6B 40 33 31 5C 63 7D 4A 47 42 51 5D 70 54 68 7D 62 32 4B 72 6A 57 3C 71 }
        $b3 = { BB 05 10 D4 BB 05 10 E0 BB 05 10 EC BB 05 10 F8 BB 05 10 04 BC 05 10 10 BC 05 10 1C BC 05 10 2C BC 05 10 3C BC 05 10 50 BC 05 10 68 BC 05 10 80 BC 05 10 90 BC 05 10 A8 BC 05 10 B4 BC 05 10 C0 }
    condition:
        1 of ($b*)
}

