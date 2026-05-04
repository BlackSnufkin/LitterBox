rule Multi_Trojan_Gosar_31dba745 {
    meta:
        author = "Elastic Security"
        id = "31dba745-8079-4161-9299-84a4c33b95c8"
        fingerprint = "87e44b3050eb33edb24ad8aa8923ed91124f2e92e4eae42e94decefc49ccbf4c"
        creation_date = "2024-11-05"
        last_modified = "2024-12-04"
        threat_name = "Multi.Trojan.Gosar"
        reference_sample = "4caf4b280e61745ce53f96f48a74dea3b69df299c3b9de78ba4731b83c76c334"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "GetRecoverAccounts"
        $a2 = "GetIsFirstScreen"
        $a3 = "DoWebcamStop"
        $a4 = "DoAskElevate"
        $a5 = "vibrant/proto/pb"
        $a6 = "vibrant/network/sender"
        $a7 = "vibrant/pkg/helpers"
    condition:
        3 of them
}

rule Multi_Trojan_Gosar_670efa04 {
    meta:
        author = "Elastic Security"
        id = "670efa04-a5c9-40b4-bcdf-453af8162a6f"
        fingerprint = "7a0f61bb77e16baceafd60d3041002bb551f64c567ef9f495362718716c53c6a"
        creation_date = "2025-09-02"
        last_modified = "2025-09-19"
        threat_name = "Multi.Trojan.Gosar"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $byte_sequence_1 = { C6 44 24 3B 00 C6 44 24 3B 01 48 89 C1 48 89 DF 48 8D 74 24 3B 41 B8 01 00 00 00 4D 89 C1 48 8B 84 24 D8 00 00 00 48 8B 9C 24 E0 00 00 00 }
        $a_clip_board0 = "<b>[CLIPBOARD_START]</b><xmp>"
        $a_clip_board1 = "</b>]</p><br>[Applications]"
        $a_clip_board2 = "replace clipboard content failed"
    condition:
        $byte_sequence_1 or all of ($a_clip_board*)
}

