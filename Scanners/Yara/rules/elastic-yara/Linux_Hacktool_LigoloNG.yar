rule Linux_Hacktool_LigoloNG_027c0134 {
    meta:
        author = "Elastic Security"
        id = "027c0134-f3f6-448f-9f44-e0ead39fce9b"
        fingerprint = "3f1662ab5723eb2e50ea468129d1bd817f77e0df1b4565d242a3fcb1225b3360"
        creation_date = "2024-09-20"
        last_modified = "2024-11-04"
        threat_name = "Linux.Hacktool.LigoloNG"
        reference_sample = "eda6037bda3ccf6bbbaf105be0826669d5c4ac205273fefe103d8c648271de54"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = "https://github.com/nicocha30/ligolo-ng"
        $b = "@Nicocha30!"
        $c = "Ligolo-ng %s / %s / %s"
    condition:
        all of them
}

