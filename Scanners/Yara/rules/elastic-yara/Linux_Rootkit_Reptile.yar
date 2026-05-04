rule Linux_Rootkit_Reptile_b2ccf852 {
    meta:
        author = "Elastic Security"
        id = "b2ccf852-1b85-4fe1-b0a7-7d39f91fee1b"
        fingerprint = "77d591ebe07ffe1eada48b3c071b1c7c21f6cc16f15eb117e7bbd8fd256e9726"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $func1 = "reptile_shell"
        $func2 = "reptile_start"
        $func3 = "reptile_module"
        $func4 = "reptile_init"
        $func5 = "reptile_exit"
    condition:
        2 of ($func*)
}

rule Linux_Rootkit_Reptile_c9f8806d {
    meta:
        author = "Elastic Security"
        id = "c9f8806d-102a-41d6-82bb-a2a136f51e67"
        fingerprint = "765329c644a95224493dcef81186504013ee5c1cda0860e4f5b31eab9857623f"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "parasite_loader"
        $str2 = "parasite_loader/encrypt"
        $str3 = "kmatryoshka.c"
        $str4 = "parasite_loader.mod.c"
        $str5 = "reptile.mod.c"
        $str6 = "parasite_blob"
        $str7 = "name=reptile"
        $loader1 = "loader.c"
        $loader2 = "custom_rol32"
        $loader3 = "do_encode"
        $blob = "_blob"
    condition:
        ((3 of ($str*)) or (all of ($loader*))) and $blob
}

rule Linux_Rootkit_Reptile_eb201301 {
    meta:
        author = "Elastic Security"
        id = "eb201301-b10b-4c88-ae45-6cceb2f6ef6e"
        fingerprint = "7f1948a9e08c3ad9db3492112590bf5f10eb7b992fe3ab5cc5fc52bf81897378"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "Reptile Packet Sender"
        $str2 = "Written by F0rb1dd3n"
        $str3 = "Reptile Wins"
        $str4 = "Written by: F0rb1dd3n"
        $opt1 = "-r Remote port from magic packets (only for tcp/udp)"
        $opt2 = "-x Magic Packet protocol (tcp/icmp/udp)"
        $opt3 = "-s Source IP address to spoof"
        $opt4 = "-q Source port from magic packets (only for tcp/udp)"
        $opt5 = "-l Host to receive the reverse shell"
        $opt6 = "-p Host port to receive the reverse shell"
        $opt7 = "-k Token to trigger the port-knocking"
        $help1 = "Run the listener and send the magic packet"
        $help2 = "Local host to receive the shell"
        $help3 = "Local port to receive the shell"
        $help4 = "Source host on magic packets (spoof)"
        $help5 = "Source port on magic packets (only for TCP/UDP)"
        $help6 = "Remote port (only for TCP/UDP)"
        $help7 = "Protocol to send magic packet (ICMP/TCP/UDP)"
        $rep1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]"
        $rep2 = "S3cr3tP@ss"
    condition:
        all of ($rep*) or (1 of ($str*) and (4 of ($opt*) or 4 of ($help*)))
}

rule Linux_Rootkit_Reptile_85abf958 {
    meta:
        author = "Elastic Security"
        id = "85abf958-1c81-4b65-ae5c-49f3e5137f07"
        fingerprint = "db0f0398bb25e96f2b46d3836fbcc056dc3ac90cfbe6ba6318fd6fa48315432b"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $byte1 = { C7 06 65 78 65 63 C7 46 04 20 62 61 73 C7 46 08 68 20 2D 2D C7 46 0C 72 63 66 69 C7 46 10 6C 65 20 00 }
        $byte2 = { C7 07 59 6F 75 20 C7 47 04 61 72 65 20 C7 47 08 61 6C 72 65 C7 47 0C 61 64 79 20 C7 47 10 72 6F 6F 74 C7 47 14 21 20 3A 29 C7 47 18 0A 0A 00 00 }
        $byte3 = { C7 47 08 59 6F 75 20 C7 47 0C 68 61 76 65 C7 47 10 20 6E 6F 20 C7 47 14 70 6F 77 65 C7 47 18 72 20 68 65 C7 47 1C 72 65 21 20 C7 47 20 3A 28 20 1B }
        $byte4 = { C7 47 08 59 6F 75 20 C7 47 0C 67 6F 74 20 C7 47 10 73 75 70 65 C7 47 14 72 20 70 6F C7 47 18 77 65 72 73 C7 47 1C 21 1B 5B 30 C7 47 20 30 6D 0A 0A }
        $byte5 = { C7 06 66 69 6C 65 C7 46 04 2D 74 61 6D C7 46 08 70 65 72 69 C7 46 0C 6E 67 00 00 }
        $str1 = "reptile"
        $str2 = "exec bash --rcfi"
    condition:
        any of ($byte*) or all of ($str*)
}

