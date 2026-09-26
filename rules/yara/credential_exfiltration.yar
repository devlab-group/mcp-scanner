/* Multi-word YARA backstop for credential harvesting and exfiltration */

rule credential_harvesting_request
{
    meta:
        title = "Description asks for credentials to be sent or pasted"
        severity = "CRITICAL"
        category = "credential_harvesting"

    strings:
        $s1 = "paste your api key" nocase
        $s2 = "paste your aws credentials" nocase
        $s3 = "send your access token" nocase
        $s4 = "provide your private key" nocase
        $s5 = "enter your ssh key" nocase

    condition:
        any of them
}

rule exfiltration_to_url
{
    meta:
        title = "Description instructs sending data to a URL"
        severity = "CRITICAL"
        category = "exfiltration"

    strings:
        $s1 = "send the results to http" nocase
        $s2 = "post the data to http" nocase
        $s3 = "upload the output to http" nocase
        $s4 = "encode the result into the url" nocase

    condition:
        any of them
}
