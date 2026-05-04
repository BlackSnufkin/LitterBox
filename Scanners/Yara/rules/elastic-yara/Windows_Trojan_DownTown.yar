rule Windows_Trojan_DownTown_901c4fdd {
    meta:
        author = "Elastic Security"
        id = "901c4fdd-858c-4ad8-be12-f88799d591b9"
        fingerprint = "1ef6dfd9be1e6fa2d1c6b5ce32ad13252f5becf709493a7cceff3519750e0b1e"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.DownTown"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "SendFileBuffer error -1 !!!" fullword
        $a2 = "ScheduledDownloadTasks CODE_FILE_VIEW " fullword
        $a3 = "ExplorerManagerC.dll" fullword
    condition:
        3 of them
}

rule Windows_Trojan_DownTown_145ecd2f {
    meta:
        author = "Elastic Security"
        id = "145ecd2f-d012-4566-a2e9-696cdbd793ce"
        fingerprint = "d755ad4a24b390ce56d4905e40cec83a39ea515cfbe7e1a534950ca858343e70"
        creation_date = "2023-08-23"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.DownTown"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "DeletePluginObject"
        $a2 = "GetPluginInfomation"
        $a3 = "GetPluginObject"
        $a4 = "GetRegisterCode"
    condition:
        all of them
}

