rule Windows_Hacktool_Rubeus_43f18623 {
    meta:
        author = "Elastic Security"
        id = "43f18623-6024-4608-8019-e3fecd54cf84"
        fingerprint = "fbc2f67f394a4d21cac532b42c6749002cb7284b4a3912e18672881e6e74765d"
        creation_date = "2022-10-20"
        last_modified = "2022-11-24"
        threat_name = "Windows.Hacktool.Rubeus"
        reference_sample = "b7b4691ad1cdad7663c32d07e911a03d9cc8b104f724c2825fd4957007649235"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide nocase
        $print_str0 = "[*] Printing argument list for use with Rubeus" ascii wide
        $print_str1 = "[+] Ticket successfully imported!" ascii wide
        $print_str2 = "[+] Tickets successfully purged!" ascii wide
        $print_str3 = "[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96" ascii wide
        $print_str4 = "[*] Action: TGT Harvesting (with auto-renewal)" ascii wide
        $print_str5 = "[X] Unable to retrieve TGT using tgtdeleg" ascii wide
        $print_str6 = "[!] Unhandled Rubeus exception:" ascii wide
        $print_str7 = "[*] Using a TGT /ticket to request service tickets" ascii wide
    condition:
        $guid or 4 of ($print_str*)
}

