rule Linux_Trojan_Springtail_35d5b90b {
    meta:
        author = "Elastic Security"
        id = "35d5b90b-f81d-4a10-828b-8315f8e87ca7"
        fingerprint = "ca2d3ea7b23c0fc21afb9cfd2d6561727780bda65d2db1a5780b627ac7b07e66"
        creation_date = "2024-05-18"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.Springtail"
        reference_sample = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $systemd1 = "Description=syslogd"
        $systemd2 = "ExecStart=/bin/sh -c \"/var/log/syslogd\""
        $cron1 = "cron.txt@reboot"
        $cron2 = "/bin/shcrontab"
        $cron3 = "type/var/log/syslogdcrontab cron.txt"
        $uri = "/mir/index.php"
    condition:
        all of them
}

