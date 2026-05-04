rule Windows_Hacktool_SharpDump_7c17d8b1 {
    meta:
        author = "Elastic Security"
        id = "7c17d8b1-35cf-440e-8f4e-44abdc2054bb"
        fingerprint = "cf1e23fc0a317959fceadae8984240b174dac22a1bcabccf43c34f0186a3ac23"
        creation_date = "2022-10-20"
        last_modified = "2022-11-24"
        threat_name = "Windows.Hacktool.SharpDump"
        reference_sample = "14c3ea569a1bd9ac3aced4f8dd58314532dbf974bfa359979e6c7b6a4bbf41ca"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "9c9bba3-a0ea-431c-866c-77004802d" ascii wide nocase
        $print_str0 = "Please use \"SharpDump.exe [pid]\" format" ascii wide
        $print_str1 = "[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch" ascii wide
        $print_str2 = "[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress" ascii wide
        $print_str3 = "[X] Not in high integrity, unable to MiniDump!" ascii wide
    condition:
        $guid or all of ($print_str*)
}

