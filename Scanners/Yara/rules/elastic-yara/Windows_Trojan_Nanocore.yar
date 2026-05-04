rule Windows_Trojan_Nanocore_d8c4e3c5 {
    meta:
        author = "Elastic Security"
        id = "d8c4e3c5-8bcc-43d2-9104-fa3774282da5"
        fingerprint = "e5c284f14c1c650ef8ddd7caf314f5318e46a811addc2af5e70890390c7307d4"
        creation_date = "2021-06-13"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Nanocore"
        reference_sample = "b2262126a955e306dc68487333394dc08c4fbd708a19afeb531f58916ddb1cfd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "NanoCore.ClientPluginHost" ascii fullword
        $a2 = "NanoCore.ClientPlugin" ascii fullword
        $b1 = "get_BuilderSettings" ascii fullword
        $b2 = "ClientLoaderForm.resources" ascii fullword
        $b3 = "PluginCommand" ascii fullword
        $b4 = "IClientAppHost" ascii fullword
        $b5 = "GetBlockHash" ascii fullword
        $b6 = "AddHostEntry" ascii fullword
        $b7 = "LogClientException" ascii fullword
        $b8 = "PipeExists" ascii fullword
        $b9 = "IClientLoggingHost" ascii fullword
    condition:
        1 of ($a*) or 6 of ($b*)
}

