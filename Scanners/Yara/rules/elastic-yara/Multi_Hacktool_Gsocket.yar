rule Multi_Hacktool_Gsocket_761d3a0f {
    meta:
        author = "Elastic Security"
        id = "761d3a0f-e2e8-4a8a-99f6-7356555a517d"
        fingerprint = "e4426c5faa5775bcfdfbe01c3d6a2b4042aa9bf942883b104c241d0734b272c9"
        creation_date = "2024-09-20"
        last_modified = "2024-11-04"
        threat_name = "Multi.Hacktool.Gsocket"
        reference_sample = "193efd61ae10f286d06390968537fa85e4df40995fd424d1afe426c089d172ab"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str1 = "gsocket: gs_funcs not found"
        $str2 = "/share/gsocket/gs_funcs"
        $str3 = "$GSOCKET_ARGS"
        $str4 = "GSOCKET_SECRET"
        $str5 = "GS_HIJACK_PORTS"
        $str6 = "sftp -D gs-netcat"
        $str7 = "GS_NETCAT_BIN"
        $str8 = "GSOCKET_NO_GREETINGS"
        $str9 = "GS-NETCAT(1)"
        $str10 = "GSOCKET_SOCKS_IP"
        $str11 = "GSOCKET_SOCKS_PORT"
        $str12 = "gsocket(1)"
        $str13 = "gs-sftp(1)"
        $str14 = "gs-mount(1)"
    condition:
        3 of them
}

