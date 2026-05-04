rule Windows_AttackSimulation_Hovercraft_f5c7178f {
    meta:
        author = "Elastic Security"
        id = "f5c7178f-9a3f-463d-96a7-0a82cbed9ba2"
        fingerprint = "8965ab173fd09582c9e77e7c54c9722b91b71ecbe42c4f8a8cc87d9a780ffe8c"
        creation_date = "2022-05-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.AttackSimulation.Hovercraft"
        reference = "046645b2a646c83b4434a893a0876ea9bd51ae05e70d4e72f2ccc648b0f18cb6"
        severity = 1
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "MyHovercraftIsFullOfEels" wide fullword
        $a2 = "WinHttp.dll" fullword
    condition:
        all of them
}

