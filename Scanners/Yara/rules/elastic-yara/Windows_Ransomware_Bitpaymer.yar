rule Windows_Ransomware_Bitpaymer_d74273b3 : beta {
    meta:
        author = "Elastic Security"
        id = "d74273b3-d109-4b5d-beff-dffee9a984b1"
        fingerprint = "4f913f06f7c7decbeb78187c566674f91ebbf929ad7057641659bb756cf2991b"
        creation_date = "2020-06-25"
        last_modified = "2021-08-23"
        description = "Identifies BITPAYMER ransomware"
        threat_name = "Windows.Ransomware.Bitpaymer"
        reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = { 24 E8 00 00 00 29 F0 19 F9 89 8C 24 88 00 00 00 89 84 24 84 00 }
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Bitpaymer_bca25ac6 : beta {
    meta:
        author = "Elastic Security"
        id = "bca25ac6-e351-4823-be75-b0661c89588a"
        fingerprint = "2ecc7884d47ca7dbba30ba171b632859914d6152601ea7b463c0f52be79ebb8c"
        creation_date = "2020-06-25"
        last_modified = "2021-08-23"
        description = "Identifies BITPAYMER ransomware"
        threat_name = "Windows.Ransomware.Bitpaymer"
        reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "RWKGGE.PDB" fullword
        $a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
        $a3 = "04QuURX.pdb" fullword
        $a4 = "9nuhuNN.PDB" fullword
        $a5 = "mHtXGC.PDB" fullword
        $a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
        $a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
        $a8 = "k:\\softcare\\release\\h2O.pdb" fullword
    condition:
        1 of ($a*)
}

