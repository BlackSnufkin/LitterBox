rule Multi_Ransomware_BlackCat_aaf312c3 {
    meta:
        author = "Elastic Security"
        id = "aaf312c3-47b4-4dab-b7fc-8a2ac9883772"
        fingerprint = "577c7f24a7ecf89a542e9a63a1744a129c96c32e8dccfbf779dd9fc6c0194930"
        creation_date = "2022-02-02"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $chacha20_enc = { EF D9 F3 0F 7F 14 3B F3 0F 7F 5C 3B 10 83 C7 20 39 F8 75 D0 8B }
        $crc32_imp = { F3 0F 6F 02 66 0F 6F D1 66 0F 3A 44 CD 11 83 C0 F0 83 C2 10 66 0F 3A 44 D4 00 83 F8 0F 66 0F EF C8 66 0F EF CA }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_00e525d7 {
    meta:
        author = "Elastic Security"
        id = "00e525d7-a8a6-475f-89ad-607c452aea1e"
        fingerprint = "631e30b8b51a5c0a0e91e8c09968663192569005b8bffff9f0474749788e9d57"
        creation_date = "2022-02-02"
        last_modified = "2022-08-16"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "ata\",\"boot\",\"config.msi\",\"google\",\"perflogs\",\"appdata\",\"windows.old\"],\"exclude_file_names\":[\"desktop.ini\",\"aut"
        $a2 = "locker::core::windows::processvssadmin.exe delete shadows /all /quietshadow_copy::remove_all=" ascii fullword
        $a3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii fullword
        $a4 = "--bypass-p-p--bypass-path-path --no-prop-servers \\\\" ascii fullword
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_c4b043e6 {
    meta:
        author = "Elastic Security"
        id = "c4b043e6-ff5f-4492-94e3-fd688d690738"
        fingerprint = "3e89858e90632ad5f4831427bd630252113b735c51f7a1aa1eab8ba6e4c16f18"
        creation_date = "2022-09-12"
        last_modified = "2022-09-29"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_70171625 {
    meta:
        author = "Elastic Security"
        id = "70171625-c29b-47c1-b572-2e6dc846a907"
        fingerprint = "f3f70f92fe9c044f4565fca519cb04a3a54536985c2614077ef92c3193fff9c1"
        creation_date = "2023-01-05"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str0 = "}RECOVER-${EXTENSION}-FILES.txt"
        $str1 = "?access-key=${ACCESS_KEY}"
        $str2 = "${NOTE_FILE_NAME}"
        $str3 = "enable_network_discovery"
        $str4 = "enable_set_wallpaper"
        $str5 = "enable_esxi_vm_kill"
        $str6 = "strict_include_paths"
        $str7 = "exclude_file_path_wildcard"
        $str8 = "${ACCESS_KEY}${EXTENSION}"
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_e066d802 {
    meta:
        author = "Elastic Security"
        id = "e066d802-b803-4e35-9b53-ae1823662483"
        fingerprint = "05037af3395b682d1831443757376064c873815ac4b6d1c09116715570f51f5d"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "00360830bf5886288f23784b8df82804bf6f22258e410740db481df8a7701525"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "esxcli vm process kill --type=force --world-id=Killing"
        $a2 = "vim-cmd vmsvc/snapshot.removeall $i"
        $a3 = "File already has encrypted extension"
    condition:
        2 of them
}

rule Multi_Ransomware_BlackCat_0ffb0a37 {
    meta:
        author = "Elastic Security"
        id = "0ffb0a37-e4c3-45be-bd4d-7033e88635aa"
        fingerprint = "319b956ddd57bea22cbee7e521649969c5b1f42ee4af49ad6f25847fb8ee9559"
        creation_date = "2023-07-29"
        last_modified = "2024-06-12"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "57136b118a0d6d3c71e522ea53e3305dae58b51f06c29cd01c0c28fa0fa34287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { C8 C8 00 00 00 89 20 00 00 45 01 00 00 32 22 08 0A 20 64 85 }
        $a2 = { 67 69 74 68 75 62 2E 63 6F 6D 2D 31 65 63 63 36 32 39 39 64 62 39 65 63 38 32 33 2F 73 69 6D 70 6C 65 6C 6F 67 2D }
    condition:
        all of them
}

