Describe 'Custom policy definitions' {
    BeforeAll {
        $script:Files = Get-ChildItem (Join-Path $PSScriptRoot '..\policies') -Filter *.json
    }
    It 'has at least one policy file' { $script:Files.Count | Should -BeGreaterThan 0 }
    It 'is valid JSON with a rule, and the effect is parameterised' {
        foreach ($f in $script:Files) {
            $p = (Get-Content $f.FullName -Raw | ConvertFrom-Json).properties
            $p.policyRule.if   | Should -Not -BeNullOrEmpty
            $p.policyRule.then | Should -Not -BeNullOrEmpty
            $p.policyRule.then.effect | Should -Be "[parameters('effect')]"
            $p.parameters.effect.allowedValues | Should -Contain 'Disabled'
        }
    }
    It 'checks compliance state, not mere existence, for AuditIfNotExists' {
        foreach ($f in $script:Files) {
            $p = (Get-Content $f.FullName -Raw | ConvertFrom-Json).properties
            if ($p.policyRule.then.effect -like '*effect*') {
                $p.policyRule.then.details.existenceCondition | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'Infrastructure as code' {
    BeforeAll { $script:Bicep = Get-ChildItem (Join-Path $PSScriptRoot '..\infra') -Filter *.bicep -Recurse }
    It 'never disables local-auth protections on the workspace' {
        (Get-Content (Join-Path $PSScriptRoot '..\infra\modules\monitoring.bicep') -Raw) | Should -Match 'disableLocalAuth:\s*true'
    }
    It 'contains no secrets or passwords' {
        foreach ($f in $script:Bicep) { (Get-Content $f.FullName -Raw) | Should -Not -Match '(?i)password\s*[:=]|sharedKey|secret\s*[:=]' }
    }
    It 'does not assign Owner to remediation identities' {
        (Get-Content (Join-Path $PSScriptRoot '..\infra\modules\governance.bicep') -Raw) | Should -Not -Match '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    }
    It 'builds with Bicep' -Skip:(-not (Get-Command az -ErrorAction SilentlyContinue)) {
        az bicep build --file (Join-Path $PSScriptRoot '..\infra\main.bicep') --stdout | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}
