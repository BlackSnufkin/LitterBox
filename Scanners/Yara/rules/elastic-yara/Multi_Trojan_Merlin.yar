rule Multi_Trojan_Merlin_32643f4c {
    meta:
        author = "Elastic Security"
        id = "32643f4c-ee47-4ed2-9807-7b85d3f4e095"
        fingerprint = "bce277ef43c67be52b67c4495652e99d4707975c79cb30b54283db56545278ae"
        creation_date = "2024-03-01"
        last_modified = "2024-05-23"
        threat_name = "Multi.Trojan.Merlin"
        reference_sample = "84b988c4656677bc021e23df2a81258212d9ceba13be204867ac1d9d706404e2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "json:\"killdate,omitempty\""
        $a2 = "json:\"maxretry,omitempty\""
        $a3 = "json:\"waittime,omitempty\""
        $a4 = "json:\"payload,omitempty\""
        $a5 = "json:\"skew,omitempty\""
        $a6 = "json:\"command\""
        $a7 = "json:\"pid,omitempty\""
        $b1 = "/merlin-agent/commands"
        $b2 = "/merlin/pkg/jobs"
        $b3 = "github.com/Ne0nd0g/merlin"
    condition:
        all of ($a*) or all of ($b*)
}

