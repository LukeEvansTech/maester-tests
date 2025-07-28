#Requires -Modules ExchangeOnlineManagement, Maester, Pester

<#
.SYNOPSIS
    Runs comprehensive Exchange Online security health checks using Maester framework
    
.DESCRIPTION
    This script executes all Exchange Online security tests from the Maester framework
    without requiring Microsoft Graph connectivity. It connects to Exchange Online only
    and generates detailed reports including CSV exports and HTML remediation guides.
    
.PARAMETER SkipConnection
    Skip the Exchange Online connection (assumes already connected)
    
.PARAMETER IncludePassedDetails
    Include full details for passed tests in the CSV export (default: only failed/skipped get full details)
    
.EXAMPLE
    .\Run-MaesterExchangeHealthCheck.ps1
    
    Runs all Exchange Online tests and generates reports in the Reports subdirectory
    
.EXAMPLE
    .\Run-MaesterExchangeHealthCheck.ps1 -SkipConnection
    
    Runs tests assuming Exchange Online connection is already established
    
.NOTES
    Author: Maester Exchange Health Check Script
    Version: 1.0
    Prerequisites:
    - Exchange Online Management PowerShell module
    - Maester PowerShell module
    - Pester PowerShell module (v5.0+)
    - Exchange Online administrative permissions
#>

[CmdletBinding()]
param(
    [switch]$SkipConnection,
    [switch]$IncludePassedDetails
)

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Set up paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$reportsPath = Join-Path $scriptPath "Reports"

# Ensure Reports directory exists
if (!(Test-Path $reportsPath)) {
    New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
    Write-Host "Created Reports directory: $reportsPath" -ForegroundColor Green
}

# Import required modules
Write-Host "`nExchange Online Security Health Check" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "`nImporting required modules..." -ForegroundColor Yellow

try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
    Import-Module Maester -ErrorAction Stop
    Write-Host "✓ All required modules loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import required modules. Please ensure ExchangeOnlineManagement, Maester, and Pester are installed."
    exit 1
}

# Connect to Exchange Online if not skipped
if (!$SkipConnection) {
    Write-Host "`nConnecting to Exchange Online..." -ForegroundColor Yellow
    try {
        Connect-ExchangeOnline -ShowBanner:$false
        Write-Host "✓ Successfully connected to Exchange Online" -ForegroundColor Green
    } catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        exit 1
    }
}

# Verify connection
$connectionInfo = Get-ConnectionInformation | Where-Object { $_.Name -like '*ExchangeOnline*' }
if (-not $connectionInfo) {
    Write-Error "No active Exchange Online connection found. Please connect first or remove -SkipConnection parameter."
    exit 1
}

Write-Host "`nConnection Details:" -ForegroundColor Cyan
Write-Host "  Tenant: $($connectionInfo.TenantId)" -ForegroundColor White
Write-Host "  User: $($connectionInfo.UserPrincipalName)" -ForegroundColor White
Write-Host "  Environment: $($connectionInfo.ConnectionUri)" -ForegroundColor White

# Get Maester module path
$maesterModule = Get-Module -ListAvailable Maester | Select-Object -First 1
if (!$maesterModule) {
    Write-Error "Maester module not found. Please install it first: Install-Module Maester"
    exit 1
}

$maesterPath = Split-Path $maesterModule.Path
$testsPath = Join-Path $maesterPath "maester-tests"

Write-Host "`nSearching for Exchange Online tests..." -ForegroundColor Yellow

# Find all test files with Exchange-related tags
$exoTestFiles = @()
$testPatterns = @(
    '-Tag.*["'']EXO["'']',           # ORCA tests use "EXO"
    '-Tag.*["'']MS\.EXO["'']'        # CISA tests use "MS.EXO"
)

# Search in relevant directories
$searchDirs = Get-ChildItem -Path $testsPath -Directory -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.Name -in @('exchange', 'orca', 'cis', 'cisa') -or 
        $_.FullName -match 'exchange|exo'
    }

foreach ($dir in $searchDirs) {
    $files = Get-ChildItem -Path $dir.FullName -Filter "*.Tests.ps1" -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach ($pattern in $testPatterns) {
                if ($content -match $pattern) {
                    if ($file.FullName -notin $exoTestFiles.FullName) {
                        $exoTestFiles += $file
                    }
                    break
                }
            }
        }
    }
}

$exoTestFiles = $exoTestFiles | Sort-Object DirectoryName, Name
Write-Host "✓ Found $($exoTestFiles.Count) Exchange Online test files" -ForegroundColor Green

# Group by test type for reporting
$fileGroups = $exoTestFiles | Group-Object { 
    if ($_.DirectoryName -match 'cisa') { 'CISA' }
    elseif ($_.DirectoryName -match 'orca') { 'ORCA' }
    elseif ($_.DirectoryName -match 'cis') { 'CIS' }
    else { 'Other' }
}

Write-Host "`nTest Distribution:" -ForegroundColor Cyan
foreach ($group in $fileGroups | Sort-Object Name) {
    Write-Host "  $($group.Name): $($group.Count) test files" -ForegroundColor White
}

# Helper function to get test documentation
function Get-TestDocumentation {
    param(
        [string]$TestName,
        [string]$TestFile
    )
    
    $documentation = @{
        Description = ""
        HowToFix = ""
        References = ""
        Impact = ""
        DefaultValue = ""
        Rationale = ""
    }
    
    # Try to find corresponding .ps1 file in public folder
    $publicPath = $TestFile -replace 'maester-tests', 'public' -replace '\.Tests\.ps1$', '.ps1'
    if (Test-Path $publicPath) {
        $cmdContent = Get-Content $publicPath -Raw
        
        # Extract description from .SYNOPSIS
        if ($cmdContent -match '\.SYNOPSIS\s*\n\s*(.+?)(?=\n\s*\.|\n#>)') {
            $documentation.Description = $matches[1].Trim()
        }
        
        # Extract description from .DESCRIPTION
        if ($cmdContent -match '\.DESCRIPTION\s*\n([\s\S]+?)(?=\n\s*\.|\n#>)') {
            $documentation.Rationale = $matches[1].Trim() -replace '\s+', ' '
        }
    }
    
    # Try to find corresponding .md file
    $mdPath = $publicPath -replace '\.ps1$', '.md'
    if (Test-Path $mdPath) {
        $mdContent = Get-Content $mdPath -Raw
        
        # Extract sections from markdown
        if ($mdContent -match '## Description\s*\n([\s\S]+?)(?=\n##|\Z)') {
            $documentation.Description = $matches[1].Trim()
        }
        if ($mdContent -match '## How to fix\s*\n([\s\S]+?)(?=\n##|\Z)') {
            $documentation.HowToFix = $matches[1].Trim()
        }
        if ($mdContent -match '## References?\s*\n([\s\S]+?)(?=\n##|\Z)') {
            $documentation.References = $matches[1].Trim()
        }
        if ($mdContent -match '## Impact\s*\n([\s\S]+?)(?=\n##|\Z)') {
            $documentation.Impact = $matches[1].Trim()
        }
        if ($mdContent -match '## Default Value\s*\n([\s\S]+?)(?=\n##|\Z)') {
            $documentation.DefaultValue = $matches[1].Trim()
        }
    }
    
    return $documentation
}

# Helper function to get remediation URL
function Get-RemediationUrl {
    param(
        [string]$TestName,
        [string]$TestType
    )
    
    $baseUrl = "https://security.microsoft.com"
    
    switch -Regex ($TestName) {
        'Spam|AntiSpam' { return "$baseUrl/antispam" }
        'Phish|AntiPhish' { return "$baseUrl/antiphishing" }
        'Safe.*Link' { return "$baseUrl/safelinks" }
        'Safe.*Attach' { return "$baseUrl/safeattachments" }
        'Malware' { return "$baseUrl/antimalware" }
        'DKIM|SPF|DMARC' { return "$baseUrl/authentication" }
        'Audit' { return "https://compliance.microsoft.com/auditlogsearch" }
        'DLP' { return "https://compliance.microsoft.com/datalossprevention" }
        'Calendar|Sharing' { return "https://admin.exchange.microsoft.com/#/organizationconfig" }
        'External.*Forward' { return "$baseUrl/antispam" }
        'Outbound.*Spam' { return "$baseUrl/antispam" }
        default { return "https://admin.microsoft.com" }
    }
}

# Initialize results collection
$detailedResults = @()
$testStartTime = Get-Date

Write-Host "`nRunning Exchange Online security tests..." -ForegroundColor Yellow
Write-Host "This may take several minutes..." -ForegroundColor DarkGray

# Process each test file
$fileCount = 0
$totalTestCount = 0

foreach ($testFile in $exoTestFiles) {
    $fileCount++
    $percentComplete = [math]::Round(($fileCount / $exoTestFiles.Count) * 100, 0)
    Write-Progress -Activity "Running Exchange Online Security Tests" -Status "Processing $($testFile.Name)" -PercentComplete $percentComplete
    
    try {
        # Run the test file
        $container = New-PesterContainer -Path $testFile.FullName
        
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Container = $container
        $pesterConfig.Run.PassThru = $true
        $pesterConfig.Output.Verbosity = 'None'
        $pesterConfig.TestResult.Enabled = $true
        
        # Run tests
        $testOutput = Invoke-Pester -Configuration $pesterConfig
        
        foreach ($test in $testOutput.Tests) {
            $totalTestCount++
            
            # Determine test metadata
            $testType = if ($testFile.DirectoryName -match 'cisa') { 'CISA' }
                       elseif ($testFile.DirectoryName -match 'orca') { 'ORCA' }
                       elseif ($testFile.DirectoryName -match 'cis') { 'CIS' }
                       else { 'Other' }
            
            # Get test documentation
            $docs = Get-TestDocumentation -TestName $test.Name -TestFile $testFile.FullName
            
            # Get remediation URL
            $remediationUrl = Get-RemediationUrl -TestName $test.Name -TestType $testType
            
            # Extract test ID from name
            $testId = if ($test.Name -match '^(ORCA\.\d+|CISA\.MS\.EXO\.\d+\.\d+|CIS\.\d+\.\d+\.\d+)') { 
                $matches[1] 
            } else { 
                $test.Name -split ':' | Select-Object -First 1 
            }
            
            # Build detailed output
            $detailOutput = ""
            if ($test.Result -eq 'Failed' -and $test.ErrorRecord) {
                $detailOutput = $test.ErrorRecord.Exception.Message
            } elseif ($test.Result -eq 'Skipped' -and $test.SkippedBecause) {
                $detailOutput = "Skipped: $($test.SkippedBecause)"
            }
            
            # Create detailed record
            $record = [PSCustomObject]@{
                TestFile = $testFile.Name
                TestType = $testType
                TestId = $testId
                TestName = $test.Name
                Result = $test.Result
                Executed = $test.Executed
                Duration = if ($test.Duration) { "{0:N2}" -f $test.Duration.TotalSeconds } else { "0.00" }
                
                # Test details
                Description = $docs.Description
                Rationale = $docs.Rationale
                Impact = $docs.Impact
                DefaultValue = $docs.DefaultValue
                
                # Result details
                ResultDetail = $detailOutput
                ErrorMessage = if ($test.ErrorRecord) { $test.ErrorRecord.Exception.Message } else { "" }
                
                # Remediation
                HowToFix = $docs.HowToFix
                RemediationUrl = $remediationUrl
                References = $docs.References
                
                # Additional context
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            $detailedResults += $record
        }
    }
    catch {
        Write-Warning "Error processing $($testFile.Name): $_"
    }
}

Write-Progress -Activity "Running Exchange Online Security Tests" -Completed

$testEndTime = Get-Date
$testDuration = $testEndTime - $testStartTime

# Generate timestamp for file names
$reportTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# Create comprehensive CSV export
Write-Host "`nGenerating reports..." -ForegroundColor Yellow

$csvPath = Join-Path $reportsPath "ExchangeHealthCheck-Results-$reportTimestamp.csv"

# Filter results based on parameter
$exportResults = if ($IncludePassedDetails) {
    $detailedResults
} else {
    # For passed tests, include minimal details
    $detailedResults | ForEach-Object {
        if ($_.Result -in @('Failed', 'Skipped')) {
            $_
        } else {
            # Create simplified record for passed tests
            [PSCustomObject]@{
                TestFile = $_.TestFile
                TestType = $_.TestType
                TestId = $_.TestId
                TestName = $_.TestName
                Result = $_.Result
                Executed = $_.Executed
                Duration = $_.Duration
                Description = $_.Description
                Rationale = ""
                Impact = ""
                DefaultValue = ""
                ResultDetail = "Test passed successfully"
                ErrorMessage = ""
                HowToFix = ""
                RemediationUrl = ""
                References = ""
                Timestamp = $_.Timestamp
            }
        }
    }
}

$exportResults | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "✓ Detailed results exported to: $(Split-Path $csvPath -Leaf)" -ForegroundColor Green

# Create executive summary
$summaryPath = Join-Path $reportsPath "ExchangeHealthCheck-Summary-$reportTimestamp.csv"

$summary = $detailedResults | Group-Object TestType, Result | ForEach-Object {
    $parts = $_.Name -split ', '
    [PSCustomObject]@{
        TestType = $parts[0]
        Result = $parts[1]
        Count = $_.Count
        TestIds = ($_.Group.TestId | Sort-Object -Unique) -join '; '
    }
} | Sort-Object TestType, Result

$summary | Export-Csv -Path $summaryPath -NoTypeInformation
Write-Host "✓ Executive summary exported to: $(Split-Path $summaryPath -Leaf)" -ForegroundColor Green

# Create HTML report for failed tests
$htmlPath = Join-Path $reportsPath "ExchangeHealthCheck-FailedTests-$reportTimestamp.html"

$failedTests = $detailedResults | Where-Object { $_.Result -eq 'Failed' } | Sort-Object TestType, TestId

# Calculate statistics
$stats = @{
    Total = $detailedResults.Count
    Passed = ($detailedResults | Where-Object {$_.Result -eq 'Passed'}).Count
    Failed = ($detailedResults | Where-Object {$_.Result -eq 'Failed'}).Count
    Skipped = ($detailedResults | Where-Object {$_.Result -eq 'Skipped'}).Count
}

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Exchange Online Security Health Check Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%); color: white; padding: 30px; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { margin: 0 0 10px 0; font-size: 32px; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .summary { background-color: white; padding: 30px; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .test-card { background-color: white; padding: 25px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #d83b01; transition: transform 0.2s; }
        .test-card:hover { transform: translateX(5px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .test-header { font-size: 20px; font-weight: 600; margin-bottom: 15px; color: #323130; }
        .test-id { color: #0078d4; font-family: 'Consolas', monospace; background-color: #f3f2f1; padding: 2px 8px; border-radius: 4px; }
        .section { margin: 15px 0; }
        .section-title { font-weight: 600; color: #605e5c; margin-bottom: 8px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
        .remediation { background-color: #e8f4fd; padding: 15px; border-radius: 6px; margin-top: 15px; border: 1px solid #b3d9f2; }
        .error { color: #d83b01; background-color: #fde7e9; padding: 15px; border-radius: 6px; margin: 15px 0; border: 1px solid #f3b3b8; }
        a { color: #0078d4; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        .stats { display: flex; justify-content: space-around; margin: 30px 0; flex-wrap: wrap; }
        .stat-box { text-align: center; padding: 25px; background-color: #f8f8f8; border-radius: 8px; flex: 1; margin: 10px; min-width: 150px; transition: transform 0.2s; }
        .stat-box:hover { transform: translateY(-5px); }
        .stat-number { font-size: 48px; font-weight: 700; color: #323130; line-height: 1; }
        .stat-label { color: #605e5c; margin-top: 8px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
        .passed { background-color: #dff6dd; }
        .failed { background-color: #fde7e9; }
        .skipped { background-color: #fff4ce; }
        .footer { text-align: center; margin-top: 50px; padding: 20px; color: #605e5c; font-size: 14px; }
        .test-details { background-color: #f8f8f8; padding: 10px; border-radius: 4px; margin-top: 10px; }
        pre { background-color: #f3f2f1; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Exchange Online Security Health Check</h1>
        <p><strong>Report Generated:</strong> $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' h:mm tt")</p>
        <p><strong>Tenant:</strong> $($connectionInfo.TenantId)</p>
        <p><strong>Environment:</strong> $($connectionInfo.ConnectionUri)</p>
        <p><strong>Test Duration:</strong> $([math]::Round($testDuration.TotalMinutes, 1)) minutes</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive security assessment of your Exchange Online configuration against industry best practices and compliance frameworks.</p>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">$($stats.Total)</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-box passed">
                <div class="stat-number">$($stats.Passed)</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-box failed">
                <div class="stat-number">$($stats.Failed)</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-box skipped">
                <div class="stat-number">$($stats.Skipped)</div>
                <div class="stat-label">Skipped</div>
            </div>
        </div>
        
        <p><strong>Compliance Score:</strong> $([math]::Round(($stats.Passed / ($stats.Total - $stats.Skipped)) * 100, 1))% of executed tests passed</p>
    </div>
    
    <h2>Failed Tests - Remediation Required</h2>
    <p>The following tests failed and require immediate attention to improve your security posture:</p>
"@

foreach ($test in $failedTests) {
    $htmlContent += @"
    <div class="test-card">
        <div class="test-header">
            <span class="test-id">$($test.TestId)</span> - $($test.TestName)
        </div>
        
        <div class="section">
            <div class="section-title">Description</div>
            <p>$($test.Description)</p>
        </div>
        
        $(if ($test.ErrorMessage) {
        "<div class='error'>
            <strong>Error Details:</strong> $($test.ErrorMessage)
        </div>"
        })
        
        $(if ($test.Impact) {
        "<div class='section'>
            <div class='section-title'>Security Impact</div>
            <p>$($test.Impact)</p>
        </div>"
        })
        
        $(if ($test.Rationale) {
        "<div class='section'>
            <div class='section-title'>Why This Matters</div>
            <p>$($test.Rationale)</p>
        </div>"
        })
        
        <div class="remediation">
            <div class="section-title">Remediation Steps</div>
            $(if ($test.HowToFix) {
                "<p>$($test.HowToFix)</p>"
            } else {
                "<p>To fix this issue, review and update the configuration in the Microsoft admin portal.</p>"
            })
            
            <p><strong>Admin Portal:</strong> <a href='$($test.RemediationUrl)' target='_blank'>$($test.RemediationUrl)</a></p>
        </div>
        
        $(if ($test.References) {
        "<div class='section'>
            <div class='section-title'>Additional References</div>
            <p>$($test.References)</p>
        </div>"
        })
    </div>
"@
}

$htmlContent += @"
    <div class="footer">
        <p>This report was generated using the Maester security assessment framework.</p>
        <p>For more information, visit <a href="https://maester.dev" target="_blank">maester.dev</a></p>
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "✓ HTML report exported to: $(Split-Path $htmlPath -Leaf)" -ForegroundColor Green

# Display summary
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "SECURITY HEALTH CHECK COMPLETED" -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`nTest Results Summary:" -ForegroundColor Yellow
Write-Host "  Total Tests Run: $($stats.Total)" -ForegroundColor White
Write-Host "  Passed: $($stats.Passed)" -ForegroundColor Green
Write-Host "  Failed: $($stats.Failed)" -ForegroundColor Red
Write-Host "  Skipped: $($stats.Skipped)" -ForegroundColor Yellow

$complianceScore = if (($stats.Total - $stats.Skipped) -gt 0) { 
    [math]::Round(($stats.Passed / ($stats.Total - $stats.Skipped)) * 100, 1) 
} else { 0 }

Write-Host "`nCompliance Score: $complianceScore%" -ForegroundColor $(
    if ($complianceScore -ge 80) { 'Green' } 
    elseif ($complianceScore -ge 60) { 'Yellow' } 
    else { 'Red' }
)

Write-Host "`nReports saved to: $reportsPath" -ForegroundColor Cyan
Write-Host "  • $(Split-Path $csvPath -Leaf) - Detailed test results" -ForegroundColor White
Write-Host "  • $(Split-Path $summaryPath -Leaf) - Executive summary" -ForegroundColor White
Write-Host "  • $(Split-Path $htmlPath -Leaf) - Failed tests remediation report" -ForegroundColor White

Write-Host "`nTest execution completed in $([math]::Round($testDuration.TotalMinutes, 1)) minutes" -ForegroundColor Green

# Disconnect if we connected
if (!$SkipConnection) {
    Write-Host "`nDisconnecting from Exchange Online..." -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

# Return results object
@{
    Results = @{
        Total = $stats.Total
        Passed = $stats.Passed
        Failed = $stats.Failed
        Skipped = $stats.Skipped
        ComplianceScore = $complianceScore
    }
    Reports = @{
        CSV = $csvPath
        Summary = $summaryPath
        HTML = $htmlPath
    }
    Duration = $testDuration
}