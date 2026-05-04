rule Windows_Ransomware_Agenda_d7b1af3f {
    meta:
        author = "Elastic Security"
        id = "d7b1af3f-fde2-437d-93e8-59364bb72c5b"
        fingerprint = "a7d45fc26aa3742daa27a8e20a703f7fda5230391f6c1ed25a4daf05f516d169"
        creation_date = "2024-09-10"
        last_modified = "2024-09-30"
        threat_name = "Windows.Ransomware.Agenda"
        reference_sample = "117fc30c25b1f28cd923b530ab9f91a0a818925b0b89b8bc9a7f820a9e630464"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $ = "-RECOVER-README.txt"
        $ = "/c vssadmin.exe delete shadows /all /quiet"
        $ = "directory_black_list"
        $ = "C:\\Users\\Public\\enc.exe"
    condition:
        all of them
}

