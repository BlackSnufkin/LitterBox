rule Windows_Hacktool_SharpHound_5adf9d6d {
    meta:
        author = "Elastic Security"
        id = "5adf9d6d-b6db-43ea-95bd-e9747b82a36d"
        fingerprint = "53d295223e2330a973f9495a7ca625c1e9429bc5daf7dda1b84b2aaeca5ea898"
        creation_date = "2022-10-20"
        last_modified = "2022-11-24"
        threat_name = "Windows.Hacktool.SharpHound"
        reference_sample = "1f74ed6e61880d19e53cde5b0d67a0507bfda0be661860300dcb0f20ea9a45f4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid0 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide nocase
        $guid1 = "90A6822C-4336-433D-923F-F54CE66BA98F" ascii wide nocase
        $print_str0 = "Initializing SharpHound at {time} on {date}" ascii wide
        $print_str1 = "SharpHound completed {Number} loops! Zip file written to {Filename}" ascii wide
        $print_str2 = "[-] Removed DCOM Collection" ascii wide
    condition:
        $guid0 or $guid1 or all of ($print_str*)
}

