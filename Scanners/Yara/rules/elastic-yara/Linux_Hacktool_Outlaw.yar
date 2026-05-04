rule Linux_Hacktool_Outlaw_cf069e73 {
    meta:
        author = "Elastic Security"
        id = "cf069e73-21f8-494c-b60e-286c033d2d55"
        fingerprint = "25169be28aa92f36a6d7cb803056efe1b7892a78120b648dc81887bc66eae89d"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        description = "Outlaw SSH bruteforce component fom the Dota3 package"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "c3efbd6b5e512e36123f7b24da9d83f11fffaf3023d5677d37731ebaa959dd27"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $ssh_key_1 = "MIIJrTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8vKBZRGKsHoCAggA"
        $ssh_key_2 = "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBC3juWsJ7DsDd2wH2XI+vUBIIJ"
        $ssh_key_3 = "UCQ2viiVV8pk3QSUOiwionAoe4j4cBP3Ly4TQmpbLge9zRfYEUVe4LmlytlidI7H"
        $ssh_key_4 = "O+bWbjqkvRXT9g/SELQofRrjw/W2ZqXuWUjhuI9Ruq0qYKxCgG2DR3AcqlmOv54g"
        $path_1 = "/home/eax/up"
        $path_2 = "/var/tmp/dota"
        $path_3 = "/dev/shm/ip"
        $path_4 = "/dev/shm/p"
        $path_5 = "/var/tmp/.systemcache"
        $cmd_1 = "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"
        $cmd_2 = "cd ~; chattr -ia .ssh; lockr -ia .ssh"
        $cmd_3 = "sort -R b | awk '{ if ( NF == 2 ) print } '> p || cat b | awk '{ if ( NF == 2 ) print } '> p; sort -R a"
        $cmd_4 = "rm -rf /var/tmp/dota*"
        $cmd_5 = "rm -rf a b c d p ip ab.tar.gz"
    condition:
        (all of ($ssh_key*)) or (3 of ($path*) and 3 of ($cmd*))
}

rule Linux_Hacktool_Outlaw_bc128a02 {
    meta:
        author = "Elastic Security"
        id = "bc128a02-ee4e-484d-ae94-9e5cf1d26e94"
        fingerprint = "7dbce4ec62eac61115a98bcf0703bfddf684e54adef2b17d31a88cdfbf52e23c"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        description = "Socat wrapper found in one of the versions of the outlaw Dota3 package"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_1 = ".templock"
        $str_2 = "Selected IP: %s\n"
        $str_3 = "Connection is working! #########"
        $str_4 = "Killed all socat processes using 'pkill -9 socat'."
        $str_5 = "socat process is running! (PID: %d)\n"
        $str_6 = "Connection to %s:%d is working!\n"
    condition:
        5 of them
}

rule Linux_Hacktool_Outlaw_2f007b58 {
    meta:
        author = "Elastic Security"
        id = "2f007b58-2041-4ef8-8bd5-3a76a6e86ece"
        fingerprint = "7fc8a66712a147a1006e053b9e957b4e6029a793850e187ec8e1c4921f454462"
        creation_date = "2025-02-28"
        last_modified = "2025-03-07"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $x64_start_thread = { 31 DB B9 10 00 00 00 4C 8B 44 24 10 48 89 D8 48 89 EF BE 7F 00 00 00 F3 48 AB 48 8B 4C 24 08 }
        $x64_main = { 4B 8B 04 F7 48 89 42 10 4B 8B 44 F7 10 48 89 42 18 4B 8B 44 F7 20 48 89 42 20 4B 8B 44 F7 08 48 89 42 28 4B 8B 44 F7 18 48 89 42 30 4B 8B 44 F7 28 48 89 42 38 4D 85 F6 74 7B }
        $x64_main_getopt = { 4C 89 EE 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 11 83 E8 48 83 F8 2E 77 E2 49 63 04 84 4C 01 E0 FF E0 }
        $x64_ip_select = { 89 C2 48 98 48 69 C0 AB AA AA 2A 89 D1 C1 F9 1F 48 C1 E8 20 29 C8 8D 0C 40 89 D0 01 C9 29 C8 83 F8 02 }
        $x86_main = { 83 C4 10 C6 04 06 00 8B 85 00 C2 FC FF 89 34 B8 83 C7 01 8B 85 10 C2 FC FF 83 EC 08 01 F8 89 85 04 C2 FC FF 89 85 0C C2 FC FF FF B5 08 C2 FC FF 6A 00 }
        $x86_main_getopt = { 83 C4 10 83 F8 FF 74 13 83 E8 48 83 F8 2E 8B 8C 83 ?? ?? ?? ?? 01 D9 FF E1 }
        $x86_ip_select = { BA AB AA AA 2A 83 C4 10 89 C1 F7 EA 89 C8 C1 F8 1F 29 C2 8D 04 52 01 C0 29 C1 83 F9 02 }
        $x86_worker = { 83 C4 10 8D 7C 24 10 90 8B 46 04 85 C0 74 4F 8B 6E 74 83 EC 0C 55 }
    condition:
        3 of ($x64*) or 3 of ($x86*)
}

