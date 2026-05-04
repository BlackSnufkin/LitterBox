rule Windows_Trojan_BlackShades_9d095c44 {
    meta:
        author = "Elastic Security"
        id = "9d095c44-5047-453e-8435-f30de94565e6"
        fingerprint = "be7d4c8200c293c3c8046d9f87b0d127ff051679ae1caeab12c533ea4309a1fc"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.BlackShades"
        reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a2 = "@*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
        $a3 = "D:\\Blackshades Project\\bs_net\\loginserver\\msvbvm60.dll\\3" ascii fullword
        $b1 = "modSniff" ascii fullword
        $b2 = "UDPFlood" ascii fullword
        $b3 = "\\nir_cmd.bss speak text " wide fullword
        $b4 = "\\pws_chro.bss" wide fullword
        $b5 = "tmrLiveLogger" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_BlackShades_be382dac {
    meta:
        author = "Elastic Security"
        id = "be382dac-6a6f-43e4-86bb-c62f0db9b43a"
        fingerprint = "e7031c42e51758358db32d8eba95f43be7dd5c4b57e6f9a76f0c3b925eae4e43"
        creation_date = "2022-02-28"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.BlackShades"
        reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 0E 4C 09 10 54 09 10 54 }
    condition:
        all of them
}

