import "pe"

rule ShadowDrop_GenericRAT {
    meta:
        description = "Detects ShadowDrop RAT based on static indicators and strings"
        author = "Plurilock"
        date = "2026-05-01"
    strings:
        $s1 = "MicrosoftEdgeUpdateCoreWrites" nocase
        $s2 = "Global\\ShdDrp_x86_mtx" nocase
        $s3 = "MicrosoftEdgeUpdateCore" nocase
        $s4 = "ShadowClient/1.0" nocase
        $s5 = "%APPDATA%\\Microsoft\\Windows\\svchost32.exe" nocase
        $s6 = "C:\\Users\\dev01\\projects\\shadowdrop\\Release\\loader.pdb" nocase
        $s7 = "Mozilla/5.0 (Windows NT 6.1; rv:60.0) ShadowClient/1.0" nocase
    condition:
        pe.is_pe and
        filesize < 5MB and
        3 of ($s*) and
        for any i in (0..pe.number_of_sections-1) : (pe.sections[i].name == ".shadow")
}