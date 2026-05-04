rule Multi_Trojan_Mythic_4beb7e17 {
    meta:
        author = "Elastic Security"
        id = "4beb7e17-34c2-4f5c-a668-e54512175f53"
        fingerprint = "0b25c5b069cec31e9af31b7822ea19b813fe1882dfaa584661ff14414ae41df5"
        creation_date = "2023-08-01"
        last_modified = "2023-09-20"
        threat_name = "Multi.Trojan.Mythic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "task_id"
        $a2 = "post_response"
        $a3 = "c2_profile"
        $a4 = "get_tasking"
        $a5 = "tasking_size"
        $a6 = "get_delegate_tasks"
        $a7 = "total_chunks"
        $a8 = "is_screenshot"
        $a9 = "file_browser"
        $a10 = "is_file"
        $a11 = "access_time"
    condition:
        7 of them
}

rule Multi_Trojan_Mythic_e0ea7ef9 {
    meta:
        author = "Elastic Security"
        id = "e0ea7ef9-452c-404c-95ba-4057ec40ef4b"
        fingerprint = "57afe989db139314a7505a2ccc01367cdd13132318dc19b57d4b79f65bfe982c"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "e091d63c8e8b0a32a3d25cffdf02419fdbec714f31e4061bafd80b1971831c5f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $profile1 = "src/profiles/mod.rs"
        $profile2 = "src/profiles/http.rs"
        $rs_ssh1 = "src/ssh/spawn.rs"
        $rs_ssh2 = "src/ssh/agent.rs"
        $rs_ssh3 = "src/ssh/cat.rs"
        $rs_ssh4 = "src/ssh/upload.rs"
        $rs_ssh5 = "src/ssh/exec.rs"
        $rs_ssh6 = "src/ssh/download.rs"
        $rs_ssh7 = "src/ssh/rm.rs"
        $rs_ssh8 = "src/ssh/ls.rs"
        $rs_misc1 = "src/utils/linux.rs"
        $rs_misc2 = "src/portscan.rs"
        $rs_misc3 = "src/payloadvars.rs"
        $rs_misc4 = "src/getprivs.rs"
    condition:
        all of ($profile*) and 8 of ($rs*)
}

rule Multi_Trojan_Mythic_528324b4 {
    meta:
        author = "Elastic Security"
        id = "528324b4-822d-4e48-b4ab-f5b234348773"
        fingerprint = "5188aa792c02acf7a6346f395389390ae187cb08083bfca27283a4f4dd4d7206"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "2cd883eab722a5eacbca7fa82e0eebb5f6c30cffa955abcb1ab8cf169af97202"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $import1 = "Autofac"
        $import2 = "Obfuscar"
        $import3 = "Agent.Profiles.Http"
        $import4 = "Agent.Managers.Linux"
        $import5 = "Agent.Managers.Reflection"
        $athena1 = "Athena.Commands.dll"
        $athena2 = "Athena.Handler.Linux.dll"
        $athena3 = "Athena.dll"
        $athena4 = "Athena.Profiles.HTTP.dll"
    condition:
        (2 of ($import*)) or (2 of ($athena*))
}

