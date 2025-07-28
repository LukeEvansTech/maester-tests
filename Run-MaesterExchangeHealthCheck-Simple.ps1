#Requires -Modules ExchangeOnlineManagement, Maester, Pester

<#
.SYNOPSIS
    Runs comprehensive Exchange Online security health checks using Maester framework (Simplified version)
    
.DESCRIPTION
    This script executes all Exchange Online security tests from the Maester framework.
    It connects to both Exchange Online and Security & Compliance Center to run all tests
    and generates CSV reports only (no HTML generation).
    
.PARAMETER SkipConnection
    Skip the Exchange Online and Security & Compliance connections (assumes already connected)
    
.PARAMETER IncludePassedDetails
    Include full details for passed tests in the CSV export (default: only failed/skipped get full details)
    
.EXAMPLE
    .\Run-MaesterExchangeHealthCheck-Simple.ps1
    
    Runs all Exchange Online tests and generates CSV reports in the Reports subdirectory
    
.EXAMPLE
    .\Run-MaesterExchangeHealthCheck-Simple.ps1 -SkipConnection
    
    Runs tests assuming Exchange Online connection is already established
    
.NOTES
    Author: Maester Exchange Health Check Script (Simplified)
    Version: 1.1
    Prerequisites:
    - Exchange Online Management PowerShell module
    - Maester PowerShell module
    - Pester PowerShell module (v5.0+)
    - Exchange Online administrative permissions
    - Security & Compliance Center administrative permissions
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
Write-Host "`nExchange Online Security Health Check (Simplified)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "`nImporting required modules..." -ForegroundColor Yellow

try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
    Import-Module Maester -ErrorAction Stop
    Write-Host "All required modules loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import required modules. Please ensure ExchangeOnlineManagement, Maester, and Pester are installed."
    exit 1
}

# Connect to Exchange Online and Security & Compliance if not skipped
if (!$SkipConnection) {
    Write-Host "`nConnecting to Exchange Online and Security & Compliance Center..." -ForegroundColor Yellow
    try {
        Connect-Maester -Service ExchangeOnline,SecurityCompliance
        Write-Host "Successfully connected to Exchange Online and Security & Compliance Center" -ForegroundColor Green
    } catch {
        Write-Error "Failed to connect to Exchange Online and Security & Compliance Center: $_"
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
Write-Host "Found $($exoTestFiles.Count) Exchange Online test files" -ForegroundColor Green

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
        if ($cmdContent -match '\.SYNOPSIS\s*\n\s*(.+?)(?=\n\s*\.|#>)') {
            $documentation.Description = $matches[1].Trim()
        }
        
        # Extract description from .DESCRIPTION
        if ($cmdContent -match '\.DESCRIPTION\s*\n([\s\S]+?)(?=\n\s*\.|#>)') {
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
Write-Host "Detailed results exported to: $(Split-Path $csvPath -Leaf)" -ForegroundColor Green

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
Write-Host "Executive summary exported to: $(Split-Path $summaryPath -Leaf)" -ForegroundColor Green

# Create failed tests text report
$failedReportPath = Join-Path $reportsPath "ExchangeHealthCheck-FailedTests-$reportTimestamp.txt"

$failedTests = $detailedResults | Where-Object { $_.Result -eq 'Failed' } | Sort-Object TestType, TestId

# Calculate statistics
$stats = @{
    Total = $detailedResults.Count
    Passed = ($detailedResults | Where-Object {$_.Result -eq 'Passed'}).Count
    Failed = ($detailedResults | Where-Object {$_.Result -eq 'Failed'}).Count
    Skipped = ($detailedResults | Where-Object {$_.Result -eq 'Skipped'}).Count
}

# Create text report content
$textContent = "EXCHANGE ONLINE SECURITY HEALTH CHECK REPORT`n"
$textContent += "==========================================`n`n"
$textContent += "Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$textContent += "Tenant: $($connectionInfo.TenantId)`n"
$textContent += "Environment: $($connectionInfo.ConnectionUri)`n"
$textContent += "Test Duration: $([math]::Round($testDuration.TotalMinutes, 1)) minutes`n`n"

$textContent += "EXECUTIVE SUMMARY`n"
$textContent += "-----------------`n"
$textContent += "Total Tests: $($stats.Total)`n"
$textContent += "Passed: $($stats.Passed)`n"
$textContent += "Failed: $($stats.Failed)`n"
$textContent += "Skipped: $($stats.Skipped)`n"

$complianceScore = if (($stats.Total - $stats.Skipped) -gt 0) { 
    [math]::Round(($stats.Passed / ($stats.Total - $stats.Skipped)) * 100, 1) 
} else { 0 }

$textContent += "Compliance Score: $complianceScore%`n`n"

if ($failedTests.Count -gt 0) {
    $textContent += "FAILED TESTS - REMEDIATION REQUIRED`n"
    $textContent += "===================================`n`n"
    
    foreach ($test in $failedTests) {
        $textContent += "Test ID: $($test.TestId)`n"
        $textContent += "Test Name: $($test.TestName)`n"
        $textContent += "Type: $($test.TestType)`n"
        $textContent += "-" * 50 + "`n"
        
        if ($test.Description) {
            $textContent += "`nDescription:`n$($test.Description)`n"
        }
        
        if ($test.ErrorMessage) {
            $textContent += "`nError Details:`n$($test.ErrorMessage)`n"
        }
        
        if ($test.Impact) {
            $textContent += "`nSecurity Impact:`n$($test.Impact)`n"
        }
        
        if ($test.Rationale) {
            $textContent += "`nWhy This Matters:`n$($test.Rationale)`n"
        }
        
        $textContent += "`nRemediation:`n"
        if ($test.HowToFix) {
            $textContent += "$($test.HowToFix)`n"
        } else {
            $textContent += "Review and update the configuration in the Microsoft admin portal.`n"
        }
        
        $textContent += "`nAdmin Portal: $($test.RemediationUrl)`n"
        
        if ($test.References) {
            $textContent += "`nReferences:`n$($test.References)`n"
        }
        
        $textContent += "`n" + "=" * 70 + "`n`n"
    }
} else {
    $textContent += "`nNo failed tests - all security checks passed!`n"
}

$textContent | Out-File -FilePath $failedReportPath -Encoding UTF8
Write-Host "Failed tests report exported to: $(Split-Path $failedReportPath -Leaf)" -ForegroundColor Green

# Display summary
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "SECURITY HEALTH CHECK COMPLETED" -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`nTest Results Summary:" -ForegroundColor Yellow
Write-Host "  Total Tests Run: $($stats.Total)" -ForegroundColor White
Write-Host "  Passed: $($stats.Passed)" -ForegroundColor Green
Write-Host "  Failed: $($stats.Failed)" -ForegroundColor Red
Write-Host "  Skipped: $($stats.Skipped)" -ForegroundColor Yellow

Write-Host "`nCompliance Score: $complianceScore%" -ForegroundColor $(
    if ($complianceScore -ge 80) { 'Green' } 
    elseif ($complianceScore -ge 60) { 'Yellow' } 
    else { 'Red' }
)

Write-Host "`nReports saved to: $reportsPath" -ForegroundColor Cyan
Write-Host "  - $(Split-Path $csvPath -Leaf) - Detailed test results" -ForegroundColor White
Write-Host "  - $(Split-Path $summaryPath -Leaf) - Executive summary" -ForegroundColor White
Write-Host "  - $(Split-Path $failedReportPath -Leaf) - Failed tests text report" -ForegroundColor White

Write-Host "`nTest execution completed in $([math]::Round($testDuration.TotalMinutes, 1)) minutes" -ForegroundColor Green

# Disconnect if we connected
if (!$SkipConnection) {
    Write-Host "`nDisconnecting from Exchange Online and Security & Compliance Center..." -ForegroundColor Yellow
    Disconnect-Maester -Service ExchangeOnline,SecurityCompliance -ErrorAction SilentlyContinue
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
        FailedTests = $failedReportPath
    }
    Duration = $testDuration
}