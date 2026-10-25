BeforeDiscovery {
    $script:ScriptFiles = Get-ChildItem (Join-Path $PSScriptRoot '..\scripts') -Filter *.ps1
}

Describe 'Script <_.Name>' -ForEach $script:ScriptFiles {
    BeforeAll {
        $script:Text = Get-Content $_.FullName -Raw
        $script:Errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$script:Errors)
    }
    It 'parses without syntax errors'            { $script:Errors | Should -BeNullOrEmpty }
    It 'enables strict mode'                     { $script:Text | Should -Match 'Set-StrictMode' }
    It 'stops on errors'                         { $script:Text | Should -Match "\`$ErrorActionPreference\s*=\s*'Stop'" }
    It 'has comment-based help'                  { $script:Text | Should -Match '\.SYNOPSIS' }
    It 'contains no embedded secrets' {
        $script:Text | Should -Not -Match '(?i)(password|sharedkey|primarysharedkey|client_?secret)\s*='
        $script:Text | Should -Not -Match '(?i)workspaceKey'
    }
    It 'does not use retired MMA tooling' {
        $script:Text | Should -Not -Match '(?i)MMASetup|OPINSIGHTS_WORKSPACE|LinkId=828603'
    }
    It 'has no Invoke-Expression' { $script:Text | Should -Not -Match '(?i)\bInvoke-Expression\b|\biex\b' }
}

Describe 'Onboard-ArcServer.ps1' {
    BeforeAll { $script:T = Get-Content (Join-Path $PSScriptRoot '..\scripts\Onboard-ArcServer.ps1') -Raw }
    It 'supports -WhatIf'                          { $script:T | Should -Match 'SupportsShouldProcess' }
    It 'sets the extension allowlist before connecting' {
        $script:T.IndexOf('extensions.allowlist') | Should -BeGreaterThan -1
        $script:T.IndexOf('extensions.allowlist') | Should -BeLessThan $script:T.IndexOf("'connect'")
    }
    It 'allows only AMA and MDE extensions' {
        $script:T | Should -Match 'AzureMonitorWindowsAgent'
        $script:T | Should -Match 'MDE\.Windows'
        $script:T | Should -Not -Match 'CustomScriptExtension|RunCommand'
    }
    It 'uses certificate auth, not a secret' {
        $script:T | Should -Match '--service-principal-cert'
        $script:T | Should -Not -Match '--service-principal-secret'
    }
    It 'checks the exit code of every azcmagent call' { $script:T | Should -Match 'LASTEXITCODE' }
}

Describe 'Get-ComplianceEvidence.ps1' {
    BeforeAll { $script:T = Get-Content (Join-Path $PSScriptRoot '..\scripts\Get-ComplianceEvidence.ps1') -Raw }
    It 'HTML-encodes finding text'        { $script:T | Should -Match 'HtmlEncode' }
    It 'pages Resource Graph results'     { $script:T | Should -Match 'SkipToken' }
    It 'excludes NotApplicable from the score' { $script:T | Should -Match "-in 'Healthy', 'Unhealthy'" }
    It 'signals SLA breaches via exit code'    { $script:T | Should -Match 'exit 2' }
}
