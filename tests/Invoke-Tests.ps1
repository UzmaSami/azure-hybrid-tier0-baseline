<# Runs all Pester tests; used locally and in CI. Writes NUnit results for the pipeline. #>
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module powershell-yaml -Scope CurrentUser -Force
$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.Exit = $true
$cfg.Output.Verbosity = 'Detailed'
$cfg.TestResult.Enabled = $true
$cfg.TestResult.OutputPath = Join-Path $PSScriptRoot 'test-results.xml'
Invoke-Pester -Configuration $cfg
