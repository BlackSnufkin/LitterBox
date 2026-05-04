rule Linux_Rootkit_Adore_fe3fd09f {
    meta:
        author = "Elastic Security"
        id = "fe3fd09f-d170-4bb0-bc8d-6d61bdc22164"
        fingerprint = "2bab2a4391359c6a7148417b010887d0754b91ac99820258e849e81f7752069f"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Adore"
        reference_sample = "f4e532b840e279daf3d206e9214a1b065f97deb7c1487a34ac5cbd7cbbf33e1a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 75 17 68 E4 A1 04 08 }
    condition:
        all of them
}

