rule Linux_Trojan_BPFDoor_59e029c3 {
    meta:
        author = "Elastic Security"
        id = "59e029c3-a57c-44ad-a554-432efc6b591a"
        fingerprint = "cc9b75b1f1230e3e2ed289ef5b8fa2deec51197e270ec5d64ff73722c43bb4e8"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
        $a3 = "avahi-daemon: chroot helper" ascii fullword
        $a4 = "/sbin/mingetty /dev/tty6" ascii fullword
        $a5 = "ttcompat" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_0f768f60 {
    meta:
        author = "Elastic Security"
        id = "0f768f60-1d6c-4af9-8ae3-c1c8fbbd32f4"
        fingerprint = "55097020a70d792e480542da40b91fd9ab0cc23f8736427f398998962e22348e"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
        $a2 = "/sbin/mingetty /dev/tty7" ascii fullword
        $a3 = "pickup -l -t fifo -u" ascii fullword
        $a4 = "kdmtmpflush" ascii fullword
        $a5 = "avahi-daemon: chroot helper" ascii fullword
        $a6 = "/sbin/auditd -n" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_8453771b {
    meta:
        author = "Elastic Security"
        id = "8453771b-a78f-439d-be36-60439051586a"
        fingerprint = "b9d07bda8909e7afb1a1411a3bad1e6cffec4a81eb47d42f2292a2c4c0d97fa7"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[-] Spawn shell failed." ascii fullword
        $a2 = "[+] Packet Successfuly Sending %d Size." ascii fullword
        $a3 = "[+] Monitor packet send." ascii fullword
        $a4 = "[+] Using port %d"
        $a5 = "decrypt_ctx" ascii fullword
        $a6 = "getshell" ascii fullword
        $a7 = "getpassw" ascii fullword
        $a8 = "export %s=%s" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f690fe3b {
    meta:
        author = "Elastic Security"
        id = "f690fe3b-1b3f-4101-931b-10932596f546"
        fingerprint = "504bfe57dcc3689881bdd0af55aab9a28dcd98e44b5a9255d2c60d9bc021130b"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 45 D8 0F B6 10 0F B6 45 FF 48 03 45 F0 0F B6 00 8D 04 02 00 }
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_1a7d804b {
    meta:
        author = "Elastic Security"
        id = "1a7d804b-9d39-4855-abe9-47b72bd28f07"
        fingerprint = "e7f92df3e3929b8296320300bb341ccc69e00d89e0d503a41190d7c84a29bce2"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "getshell" ascii fullword
        $a2 = "/sbin/agetty --noclear tty1 linux" ascii fullword
        $a3 = "packet_loop" ascii fullword
        $a4 = "godpid" ascii fullword
        $a5 = "ttcompat" ascii fullword
        $a6 = "decrypt_ctx" ascii fullword
        $a7 = "rc4_init" ascii fullword
        $b1 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 }
    condition:
        all of ($a*) or 1 of ($b*)
}

rule Linux_Trojan_BPFDoor_e14b0b79 {
    meta:
        author = "Elastic Security"
        id = "e14b0b79-a6f3-4fb3-a314-0ec20dcd242c"
        fingerprint = "1c4cb6c8a255840c5a2cb7674283678686e228dc2f2a9304fa118bb5bdc73968"
        creation_date = "2022-05-10"
        last_modified = "2022-05-10"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "getpassw" ascii fullword
        $a2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii fullword
        $a3 = "/var/run/haldrund.pid" ascii fullword
        $a4 = "Couldn't install filter %s: %s" ascii fullword
        $a5 = "godpid" ascii fullword
    condition:
        all of them
}

rule Linux_Trojan_BPFDoor_f1cd26ad {
    meta:
        author = "Elastic Security"
        id = "f1cd26ad-dffb-421f-88f1-a812769d70ff"
        fingerprint = "fb70740218e4b06c3f34cef2d3b02e67172900e067723408bcd41d4d6ca7c399"
        creation_date = "2023-05-11"
        last_modified = "2023-05-16"
        threat_name = "Linux.Trojan.BPFDoor"
        reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
        reference_sample = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $magic_bytes_check = { 0F C8 0F CA 3D 9F CD 30 44 ?? ?? ?? ?? ?? ?? 81 FA 66 27 14 5E }
        $seq_binary = { 48 C1 E6 08 48 C1 E0 14 48 01 F0 48 01 C8 89 E9 48 C1 E8 20 29 C1 D1 E9 01 C8 C1 E8 0B 83 C0 01 89 C6 C1 E6 0C }
        $signals_setup = { BE 01 00 00 00 BF 02 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 01 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 03 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 0D 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 16 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 15 00 00 00 ?? ?? ?? ?? ?? BE 01 00 00 00 BF 11 00 00 00 ?? ?? ?? ?? ?? BF 0A 00 00 00 }
    condition:
        ($magic_bytes_check and $seq_binary) or $signals_setup
}

