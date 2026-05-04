rule Windows_Trojan_DoubleLoader_3660c98a {
    meta:
        author = "Elastic Security"
        id = "3660c98a-0d39-4c21-a526-8c2e45e50dc0"
        fingerprint = "8f24627393b2d905c0cc86ec6fe32341e0cb3dab9f79df2b0e24ed43ff8442ba"
        creation_date = "2025-02-05"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.DoubleLoader"
        reference_sample = "d94f7224a065a09a9f0c116bcb021bae2e941e2cd544eb0a0b1d1a325ae87667"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "GetSettingsFromRegistry failed" ascii fullword
        $str2 = "Install persistence failed" ascii fullword
        $str3 = "Connect to remote port using Afd driver failed" ascii fullword
        $str4 = "/obfdownload/DoubleLoaderDll.dll" ascii fullword
        $str5 = "Invalid response status code for download file. not 200 OK" ascii fullword
        $str6 = "Failed to send HTTP/1.1 request to server for download file" ascii fullword
        $path = "D:\\projects\\DoubleLoader_net4\\DoubleLoader\\x64\\Release\\Loader.pdb" ascii fullword
        $path2 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\sha_simd.cpp" ascii fullword
        $path3 = "d:\\projects\\doubleloader_net4\\doubleloader\\cryptopp\\gf2n_simd.cpp" ascii fullword
    condition:
        4 of ($str*) or 1 of ($path*)
}

