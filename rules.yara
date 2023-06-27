/*
structure of yara rule

*/
/*rule test{

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

}*/

rule ExeFileRule 
{
    meta:
        description = "YARA rule for detecting .exe files"
    strings:
        $mz_signature = { 4D 5A }    // MZ signature at the beginning of file
        $pe_signature = { 50 45 00 00 }    // PE signature 
    condition:
        $mz_signature at 0 and $pe_signature at $mz_signature + 0x3C
}

rule Regex
{
    meta:
        description = "Matches any numbers,chars that are 6 long"
    strings:
        $reg = /[\w\d]{6}/ /*containing any char or num and is 6 long*/
    condition:
        $reg 
}

rule Websites
{
    meta:
        description = "Everything that has text/html as a content header, most common websites"
    
    strings:
        $httpHeader = "Content-Type: text/html "
    condition:
        $httpHeader
}

rule Hexsignatures
{
    meta:
        description = "Matches Hex Signature of PDF and PNG"
    strings:
        $HEX_PDF = {25 50 44 46}
        $HEX_PNG = {89 50 4E 47 0D 0A 1A 0A}
    condition:
        any of them

}

rule URL
{
    meta:
        description = "Detection of any URL or the Name of CEO"
    strings:
        $Regex_URL = /https?:\/\/([\w\.-]+)([\/\w\.-]*)/
        $CEO = "Bob Kent" nocase
    condition:
        $Regex_URL or $CEO
}
/*
apply to all rules for files < 2MB
*/
global rule SmallFileSizeRule 
{
    meta:
        description = "YARA rule for detecting files smaller than 2 MB"
    condition:
        filesize < 2MB
}
