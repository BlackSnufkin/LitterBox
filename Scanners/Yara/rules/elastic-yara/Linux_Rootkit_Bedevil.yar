rule Linux_Rootkit_Bedevil_2af79cea {
    meta:
        author = "Elastic Security"
        id = "2af79cea-f861-4db6-9036-ee6aeb96acd6"
        fingerprint = "293f3a8a126f2f271f8ecc9dcb3a9d19338f79aeec2d9d5fdc66e198b1e45298"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Bedevil"
        reference_sample = "8f8c598350632b32e72cd6af3a0ca93c05b4d9100fd03e2ae1aec97a946eb347"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "bdvinstall"
        $str2 = "putbdvlenv"
        $str3 = "bdvprep"
        $str4 = "bdvcleanse"
        $str5 = "dobdvutil"
        $str6 = "forge_maps"
        $str7 = "forge_smaps"
        $str8 = "forge_numamaps"
        $str9 = "forge_procnet"
        $str10 = "secret_connection"
        $str11 = "dropshell"
    condition:
        4 of ($str*)
}

