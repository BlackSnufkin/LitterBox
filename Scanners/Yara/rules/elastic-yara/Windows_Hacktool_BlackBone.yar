rule Windows_Hacktool_BlackBone_2ff5ec38 {
    meta:
        author = "Elastic Security"
        id = "2ff5ec38-ce35-432a-8ffa-d459f84438dd"
        fingerprint = "e3df60931c040081214296f006d98e155a5dc7e285a840a1decb23186ef67465"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.BlackBone"
        reference_sample = "4e3887f950bff034efedd40f1e949579854a24140128246fa6141f2c34de6017"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "BlackBone: %s: ZwCreateThreadEx hThread 0x%X"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

