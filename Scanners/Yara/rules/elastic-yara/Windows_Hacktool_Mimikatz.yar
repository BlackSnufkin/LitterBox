rule Windows_Hacktool_Mimikatz_1388212a {
    meta:
        author = "Elastic Security"
        id = "1388212a-2146-4565-b93d-4555a110364f"
        fingerprint = "dbbdc492c07e3b95d677044751ee4365ec39244e300db9047ac224029dfe6ab7"
        creation_date = "2021-04-13"
        last_modified = "2021-08-23"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "   Password: %s" wide fullword
        $a2 = "  * Session Key   : 0x%08x - %s" wide fullword
        $a3 = "   * Injecting ticket : " wide fullword
        $a4 = " ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" wide fullword
        $a5 = "Remove mimikatz driver (mimidrv)" wide fullword
        $a6 = "mimikatz(commandline) # %s" wide fullword
        $a7 = "  Password: %s" wide fullword
        $a8 = " - SCardControl(FEATURE_CCID_ESC_COMMAND)" wide fullword
        $a9 = " * to 0 will take all 'cmd' and 'mimikatz' process" wide fullword
        $a10 = "** Pass The Ticket **" wide fullword
        $a11 = "-> Ticket : %s" wide fullword
        $a12 = "Busylight Lync model (with bootloader)" wide fullword
        $a13 = "mimikatz.log" wide fullword
        $a14 = "Log mimikatz input/output to file" wide fullword
        $a15 = "ERROR kuhl_m_dpapi_masterkey ; kull_m_dpapi_unprotect_domainkey_with_key" wide fullword
        $a16 = "ERROR kuhl_m_lsadump_dcshadow ; unable to start the server: %08x" wide fullword
        $a17 = "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation (0x%08x)" wide fullword
        $a18 = "ERROR mimikatz_doLocal ; \"%s\" module not found !" wide fullword
        $a19 = "Install and/or start mimikatz driver (mimidrv)" wide fullword
        $a20 = "Target: %hhu (0x%02x - %s)" wide fullword
        $a21 = "mimikatz Ho, hey! I'm a DC :)" wide fullword
        $a22 = "mimikatz service (mimikatzsvc)" wide fullword
        $a23 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " wide fullword
        $a24 = "$http://blog.gentilkiwi.com/mimikatz 0" ascii fullword
        $a25 = " * Username : %wZ" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Hacktool_Mimikatz_674fd079 {
    meta:
        author = "Elastic Security"
        id = "674fd079-f7fe-4d89-87e7-ac11aa21c9ed"
        fingerprint = "b8f71996180e5f03c10e39eb36b2084ecaff78d7af34bd3d0d75225d2cfad765"
        creation_date = "2021-04-14"
        last_modified = "2021-08-23"
        description = "Detection for default mimikatz memssp module"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
        severity = 99
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 44 30 00 38 00 }
        $a2 = { 48 78 00 3A 00 }
        $a3 = { 4C 25 00 30 00 }
        $a4 = { 50 38 00 78 00 }
        $a5 = { 54 5D 00 20 00 }
        $a6 = { 58 25 00 77 00 }
        $a7 = { 5C 5A 00 5C 00 }
        $a8 = { 60 25 00 77 00 }
        $a9 = { 64 5A 00 09 00 }
        $a10 = { 6C 5A 00 0A 00 }
        $a11 = { 68 25 00 77 00 }
        $a12 = { 68 25 00 77 00 }
        $a13 = { 6C 5A 00 0A 00 }
        $b1 = { 6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67 }
    condition:
        all of ($a*) or $b1
}

rule Windows_Hacktool_Mimikatz_355d5d3a {
    meta:
        author = "Elastic Security"
        id = "355d5d3a-e50e-4614-9a84-0da668c40852"
        fingerprint = "9a23845ec9852d2490171af111612dc257a6b21ad7fdfd8bf22d343dc301d135"
        creation_date = "2021-04-14"
        last_modified = "2021-08-23"
        description = "Detection for Invoke-Mimikatz"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "945245ca795e0a3575ee4fdc174df9d377a598476c2bf4bf0cdb0cde4286af96"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "$PEBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $a2 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $b1 = "Write-BytesToMemory -Bytes $Shellcode"
        $b2 = "-MemoryAddress $GetCommandLineWAddrTemp"
        $b3 = "-MemoryAddress $GetCommandLineAAddrTemp"
        $c1 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword
        $c2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam"
        $c3 = "at: http://blog.gentilkiwi.com"
        $c4 = "on the local computer to dump certificates."
        $c5 = "Throw \"Unable to write shellcode to remote process memory.\"" fullword
        $c6 = "-Command \"privilege::debug exit\" -ComputerName \"computer1\""
        $c7 = "dump credentials without"
        $c8 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword
        $c9 = "two remote computers to dump credentials."
        $c10 = "#If a remote process to inject in to is specified, get a handle to it" fullword
    condition:
        (1 of ($a*) or 2 of ($b*)) or 5 of ($c*)
}

rule Windows_Hacktool_Mimikatz_71fe23d9 {
    meta:
        author = "Elastic Security"
        id = "71fe23d9-ee1a-47fb-a99f-2be2eb9ccb1a"
        fingerprint = "22b1f36e82e604fc3a80bb5abf87aef59957b1ceeb050eea3c9e85fb0b937db1"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Benjamin Delpy"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "856687718b208341e7caeea2d96da10f880f9b5a75736796a1158d4c8755f678"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_Hacktool_Mimikatz_b393864f {
    meta:
        author = "Elastic Security"
        id = "b393864f-a9b0-47e7-aea4-0fc5a4a22a82"
        fingerprint = "bfd497290db97b7578d59e8d43a28ee736a3d7d23072eb67d28ada85cac08bd3"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Subject: Open Source Developer, Benjamin Delpy"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "8206ce9c42582ac980ff5d64f8e3e310bc2baa42d1a206dd831c6ab397fbd8fe"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_Hacktool_Mimikatz_1ff74f7e {
    meta:
        author = "Elastic Security"
        id = "1ff74f7e-ec5a-45ae-b51b-2f8205445cc8"
        fingerprint = "6775be439ad1822bcaa04ed2d392143616746cfd674202aa29773c98642346f4"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "1b6aad500d45de7b076942d31b7c3e77487643811a335ae5ce6783368a4a5081"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 74 65 48 8B 44 24 28 0F B7 80 E0 00 00 00 83 F8 10 75 54 48 8B 44 }
        $a2 = { 74 69 48 8B 44 24 28 0F B7 80 D0 00 00 00 83 F8 10 75 58 48 8B 44 }
    condition:
        all of them
}

