rule Linux_Trojan_FinalDraft_4ea5a204 {
    meta:
        author = "Elastic Security"
        id = "4ea5a204-5136-42c2-80f0-634368936296"
        fingerprint = "86cc29da59c8801d7443851e2c16f04d187de9705b16cc7fca553ea09baf0eb8"
        creation_date = "2025-01-23"
        last_modified = "2025-02-04"
        threat_name = "Linux.Trojan.FinalDraft"
        reference_sample = "83406905710e52f6af35b4b3c27549a12c28a628c492429d3a411fdb2d28cc8c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_comm_option_1 = "CBindTcpTransChannel"
        $str_comm_option_2 = "CDnsTransChannel"
        $str_comm_option_3 = "CHttpTransChannel"
        $str_comm_option_4 = "CIcmpTransChannel"
        $str_comm_option_5 = "COutLookTransChannel"
        $str_comm_option_6 = "CReverseTcpTransChannel"
        $str_comm_option_7 = "CReverseUdpTransChannel"
        $str_comm_option_8 = "CWebTransChannel"
        $str_feature_1 = "%s?type=del&id=%s" fullword
        $str_feature_2 = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&grant_type=refresh_token" fullword
        $str_feature_3 = "/var/log/installlog.log.%s" fullword
        $str_feature_4 = "/mnt/hgfsdisk.log.%s" fullword
        $str_feature_5 = "%-10s %-25s %-25s %-15s" fullword
        $str_feature_6 = "%-20s %-10s %-10s %-10s %-30s" fullword
        $str_feature_7 = { 48 39 F2 74 ?? 48 0F BE 0A 48 FF C2 48 6B C0 ?? 48 01 C8 EB ?? }
    condition:
        (1 of ($str_comm_option*)) and (3 of ($str_feature_*))
}

