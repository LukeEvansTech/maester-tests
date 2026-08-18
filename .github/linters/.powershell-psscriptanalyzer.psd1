@{
    # PSAvoidUsingWriteHost is excluded deliberately.
    #
    # Both scripts here are interactive operator tools: an administrator runs
    # them at a console and reads a colour-coded Exchange Online security
    # health-check report as it streams (green for pass, red for fail, yellow
    # for warnings). The colour IS the interface. They are not library code and
    # nothing consumes their stdout as data - the machine-readable output goes
    # to test_results.csv and to the exported executive summary instead.
    #
    # The rule's stated rationale ("cannot be suppressed, captured, or
    # redirected") describes PowerShell 4 and earlier. Since 5.0 Write-Host
    # writes to the information stream and is both capturable and redirectable,
    # so the objection does not apply to either of these scripts.
    #
    # Matches the same exclusion, for the same reason, in LukeEvansTech/veeam-config.
    # Every other default rule stays enabled - including
    # PSAvoidUsingPositionalParameters, which caught a genuine output bug here
    # (Write-Host "x" + $y prints a literal '+', because -Object takes the
    # remaining arguments positionally).
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
