/* YARA backstop for instruction overrides and fake turns; qualifiers do not suppress matches */

rule prompt_injection_override
{
    meta:
        title = "Declared text tries to override the model's instructions"
        severity = "HIGH"
        category = "instruction_override"

    strings:
        $s1 = "ignore previous instructions" nocase
        $s2 = "ignore all previous instructions" nocase
        $s3 = "disregard your system prompt" nocase
        $s4 = "you are now in developer mode" nocase
        $s5 = "you are now jailbroken" nocase

    condition:
        any of them
}

rule prompt_injection_fake_turn
{
    meta:
        title = "Declared text fakes a system chat turn"
        severity = "HIGH"
        category = "instruction_override"

    strings:
        $sys = /(^|\n)\s*system\s*:\s*you (must|should|will)/ nocase

    condition:
        $sys
}
