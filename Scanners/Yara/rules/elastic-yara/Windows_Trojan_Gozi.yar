rule Windows_Trojan_Gozi_fd494041 {
    meta:
        author = "Elastic Security"
        id = "fd494041-3fe8-4ffa-9ab8-6798032f1d66"
        fingerprint = "faabcdfb3402a5951ff1fde4f994dcb00ec9a71fb815b80dc1da9b577bf92ec2"
        creation_date = "2021-03-22"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Gozi"
        reference_sample = "0a1c1557bdb8c1b99e2b764fc6b21a07e33dc777b492a25a55cbd8737031e237"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/C ping localhost -n %u && del \"%s\"" wide fullword
        $a2 = "/C \"copy \"%s\" \"%s\" /y && \"%s\" \"%s\"" wide fullword
        $a3 = "/C \"copy \"%s\" \"%s\" /y && rundll32 \"%s\",%S\"" wide fullword
        $a4 = "ASCII.GetString(( gp \"%S:\\%S\").%s))',0,0)" wide
        $a5 = "filename=\"%.4u.%lu\""
        $a6 = "Urundll32 \"%s\",%S" wide fullword
        $a7 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii fullword
        $a8 = "%08X-%04X-%04X-%04X-%08X%04X" ascii fullword
        $a9 = "&whoami=%s" ascii fullword
        $a10 = "%u.%u_%u_%u_x%u" ascii fullword
        $a11 = "size=%u&hash=0x%08x" ascii fullword
        $a12 = "&uptime=%u" ascii fullword
        $a13 = "%systemroot%\\system32\\c_1252.nls" ascii fullword
        $a14 = "IE10RunOnceLastShown_TIMESTAMP" ascii fullword
    condition:
        8 of ($a*)
}

rule Windows_Trojan_Gozi_261f5ac5 {
    meta:
        author = "Elastic Security"
        id = "261f5ac5-7800-4580-ac37-80b71c47c270"
        fingerprint = "cbc8fec8fbaa809cfc7da7db72aeda43d4270f907e675016cbbc2e28e7b8553c"
        creation_date = "2019-08-02"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Gozi"
        reference_sample = "31835c6350177eff88265e81335a50fcbe0dc46771bf031c836947851dcebb4f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
        $a2 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
        $a3 = "Content-Disposition: form-data; name=\"upload_file\"; filename=\"%.4u.%lu\""
        $a4 = "&tor=1"
        $a5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)"
        $a6 = "http://constitution.org/usdeclar.txt"
        $a7 = "grabs="
        $a8 = "CHROME.DLL"
        $a9 = "Software\\AppDataLow\\Software\\Microsoft\\"
    condition:
        4 of ($a*)
}

