rule MacOS_Hacktool_Bifrost_39bcbdf8 {
    meta:
        author = "Elastic Security"
        id = "39bcbdf8-86dc-480e-8822-dc9832bb9b55"
        fingerprint = "e11f6f3a847817644d40fee863e168cd2a18e8e0452482c1e652c11fe8dd769e"
        creation_date = "2021-10-12"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Hacktool.Bifrost"
        reference_sample = "e2b64df0add316240b010db7d34d83fc9ac7001233259193e5a72b6e04aece46"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "[dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword
        $s2 = "[-] Error in parseKirbi: %s"
        $s3 = "[-] Error in parseTGSREP: %s"
        $s4 = "genPasswordHashPassword:Length:Enc:Username:Domain:Pretty:"
        $s5 = "storeLKDCConfDataFriendlyName:Hostname:Password:CCacheName:"
        $s6 = "bifrostconsole-"
        $s7 = "-kerberoast"
        $s8 = "asklkdcdomain"
        $s9 = "askhash"
    condition:
        3 of them
}

