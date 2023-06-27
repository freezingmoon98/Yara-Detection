/*
structure of yara rule

*/
rule test{

    meta:
        author = "VALUE"
        date = " "
        version = " "
        description = "This is the structure of a rule "

    strings:
        $a = " "
        $hex = { }

    condition:
        any of them

}

rule ExeFileRule {
    meta:
        description = "YARA rule for detecting .exe files"
    strings:
        $mz_signature = { 4D 5A }    // MZ signature at the beginning of file
        $pe_signature = { 50 45 00 00 }    // PE signature 
    condition:
        $mz_signature at 0 and $pe_signature at $mz_signature + 0x3C
}

/*
apply to all rules for files < 2MB
*/
global rule SmallFileSizeRule {
    meta:
        description = "YARA rule for detecting files smaller than 2 MB"
    condition:
        filesize < 2MB
}
