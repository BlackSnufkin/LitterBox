rule Linux_Trojan_Zerobot_185e2396 {
    meta:
        author = "Elastic Security"
        id = "185e2396-f9eb-42e6-b78b-f8c01dbd3fd8"
        fingerprint = "f7ce4eebd5f13af3a480dfe23d86394c7e0f85f284a7c2900ab3fad944b08752"
        creation_date = "2022-12-16"
        last_modified = "2024-02-13"
        description = "Strings found in the zerobot startup / persistanse functions"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $startup_method_1_0 = "/usr/bin/sshf"
        $startup_method_1_1 = "start on filesystem"
        $startup_method_1_2 = "exec /usr/bin/sshf"
        $startup_method_2_0 = "Description=Hehehe"
        $startup_method_2_1 = "/lib/systemd/system/sshf.service"
        $start_service_0 = "service enable sshf"
        $start_service_1 = "systemctl enable sshf"
    condition:
        (all of ($startup_method_1_*) or all of ($startup_method_2_*)) and 1 of ($start_service_*)
}

rule Linux_Trojan_Zerobot_3a5b56dd {
    meta:
        author = "Elastic Security"
        id = "3a5b56dd-e829-44bb-ae70-d7001addd057"
        fingerprint = "9800a241ab602434426830110ce244cdfd0023176e5fa64e2b8761234ed6f529"
        creation_date = "2022-12-16"
        last_modified = "2024-02-13"
        description = "Strings found in the Zerobot Spoofed Header method"
        threat_name = "Linux.Trojan.Zerobot"
        reference_sample = "f9fc370955490bdf38fc63ca0540ce1ea6f7eca5123aa4eef730cb618da8551f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $HootSpoofHeader_0 = "X-Forwarded-Proto: Http"
        $HootSpoofHeader_1 = "X-Forwarded-Host: %s, 1.1.1.1"
        $HootSpoofHeader_2 = "Client-IP: %s"
        $HootSpoofHeader_3 = "Real-IP: %s"
        $HootSpoofHeader_4 = "X-Forwarded-For: %s"
    condition:
        3 of them
}

