/*
    XWorm detections
    Nader Ayman (Artful Dodger)
    https://artfuldodger10.github.io/posts/Xworm-Analysis/

    XWorm_Payload_Generic             family rule, any build
    XWorm_Campaign_202609_Payload     the V7.1 build from the September 2026 campaign
    XWorm_Campaign_202609_PS_Loader   stage 2 PowerShell loader from the same campaign
*/

import "pe"

rule XWorm_Payload_Generic
{
    meta:
        description = "XWorm .NET payload, matched on the C2 command names in the #US heap"
        author      = "Nader Ayman (Artful Dodger)"
        date        = "2026-09-28"
        family      = "XWorm"
        reference   = "https://artfuldodger10.github.io/posts/Xworm-Analysis/"
        hash        = "9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d"
        tested      = "9/9 payloads V3.0-V7.4, 0 hits on System32"

    strings:
        // V3.0 lacks RunShell and RemovePlugins, hence 7 of 12
        $c1  = "StartDDos" wide
        $c2  = "StopDDos" wide
        $c3  = "PCShutdown" wide
        $c4  = "PCRestart" wide
        $c5  = "PCLogoff" wide
        $c6  = "RunShell" wide
        $c7  = "OfflineGet" wide
        $c8  = "Xchat" wide
        $c9  = "savePlugin" wide
        $c10 = "RemovePlugins" wide
        $c11 = "StartReport" wide
        $c12 = "StopReport" wide

    condition:
        uint16(0) == 0x5A4D
        and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0
        and filesize < 2MB
        and 7 of ($c*)
}

rule XWorm_Campaign_202609_Payload
{
    meta:
        description = "XWorm V7.1 build delivered by RAR > JS > PowerShell > MSBuild, September 2026"
        author      = "Nader Ayman (Artful Dodger)"
        date        = "2026-09-28"
        family      = "XWorm"
        reference   = "https://artfuldodger10.github.io/posts/Xworm-Analysis/"
        hash        = "9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d"

    strings:
        $mutex = "aGO284VKfQVe8Vup" wide
        $ns1   = "AC1_1.OrderWorkflow" ascii wide
        $ns2   = "ProcessFulfillment" ascii wide
        $alg   = "AlgorithmAES" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and ($mutex or all of ($ns*, $alg))
}

rule XWorm_Campaign_202609_PS_Loader
{
    meta:
        description = "PowerShell loader that decodes and decrypts XWorm and loads it into MSBuild"
        author      = "Nader Ayman (Artful Dodger)"
        date        = "2026-09-28"
        family      = "XWorm loader"
        reference   = "https://artfuldodger10.github.io/posts/Xworm-Analysis/"

    strings:
        $f1 = "Read-StreamConfig" ascii nocase
        $f2 = "StreamHelper" ascii
        $p1 = "SysWOW64\\WindowsPowerShell" ascii wide nocase
        $p2 = "(goto) 2>nul & del" ascii
        $p3 = "Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe" ascii wide nocase
        $p4 = "CurrentDomain.Load" ascii nocase
        $k1 = { 2F EF CA F8 36 D3 4A A0 7E 83 12 96 01 8F A1 75
                5F CA 46 B7 AD 30 2E C8 84 E8 6A 18 80 1E AE E7 }

    condition:
        filesize < 5MB
        and ($k1 or ($f1 and 1 of ($f2, $p*)) or 3 of ($p*))
}
