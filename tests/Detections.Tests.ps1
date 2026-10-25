BeforeDiscovery {
    $script:RuleFiles = Get-ChildItem (Join-Path $PSScriptRoot '..\detections\rules') -Filter *.yaml
}

BeforeAll {
    Import-Module powershell-yaml -ErrorAction Stop
    $script:Rules = Get-ChildItem (Join-Path $PSScriptRoot '..\detections\rules') -Filter *.yaml |
        ForEach-Object { [pscustomobject]@{ File = $_.Name; Rule = (Get-Content $_.FullName -Raw | ConvertFrom-Yaml) } }
}

Describe 'Detection rule set' {
    It 'has at least six rules' { $script:Rules.Count | Should -BeGreaterOrEqual 6 }
    It 'has unique ids' {
        ($script:Rules.Rule.id | Select-Object -Unique).Count | Should -Be $script:Rules.Count
    }
    It 'has unique names' {
        ($script:Rules.Rule.name | Select-Object -Unique).Count | Should -Be $script:Rules.Count
    }
}

Describe 'Rule <_.Name>' -ForEach $script:RuleFiles {
    BeforeAll { $script:R = Get-Content $_.FullName -Raw | ConvertFrom-Yaml }

    It 'has a valid GUID id'           { [guid]::TryParse($script:R.id, [ref][guid]::Empty) | Should -BeTrue }
    It 'is a Scheduled rule'           { $script:R.kind | Should -Be 'Scheduled' }
    It 'has a valid severity'          { $script:R.severity | Should -BeIn 'Informational', 'Low', 'Medium', 'High' }
    It 'has a description'             { $script:R.description.Trim().Length | Should -BeGreaterThan 20 }
    It 'declares a data connector'     { @($script:R.requiredDataConnectors).Count | Should -BeGreaterThan 0 }
    It 'has a valid frequency/period'  {
        $script:R.queryFrequency | Should -Match '^\d+[mhd]$'
        $script:R.queryPeriod    | Should -Match '^\d+[mhd]$'
    }
    It 'looks back at least as far as it runs' {
        $mins = { param($v) $n = [int]($v -replace '\D'); switch -Regex ($v) { 'm$' { $n } 'h$' { $n * 60 } 'd$' { $n * 1440 } } }
        (& $mins $script:R.queryPeriod) | Should -BeGreaterOrEqual (& $mins $script:R.queryFrequency)
    }
    It 'maps to MITRE tactics and techniques' {
        @($script:R.tactics).Count | Should -BeGreaterThan 0
        foreach ($t in @($script:R.relevantTechniques)) { $t | Should -Match '^T\d{4}(\.\d{3})?$' }
    }
    It 'has a non-empty query with balanced brackets' {
        $q = $script:R.query
        $q.Trim().Length | Should -BeGreaterThan 10
        ([regex]::Matches($q, '\(').Count) | Should -Be ([regex]::Matches($q, '\)').Count)
    }
    It 'has entity mappings whose columns appear in the query' {
        @($script:R.entityMappings).Count | Should -BeGreaterThan 0
        foreach ($m in $script:R.entityMappings) {
            foreach ($f in $m.fieldMappings) {
                $script:R.query | Should -Match ([regex]::Escape($f.columnName)) -Because "column '$($f.columnName)' must be produced by the query"
            }
        }
    }
}
