#Requires -Modules Az.Accounts, powershell-yaml
<#
.SYNOPSIS
    Deploys detections/rules/*.yaml as Sentinel scheduled analytics rules (idempotent PUT by rule id).
.EXAMPLE
    .\Deploy-SentinelRules.ps1 -ResourceGroup rg-secops-monitoring-lab -WorkspaceName law-secops-lab-uksouth -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [string]$RulesPath = (Join-Path $PSScriptRoot '..\detections\rules'),
    [string]$ApiVersion = '2023-02-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-IsoDuration([string]$Value) {
    if ($Value -notmatch '^(\d+)([mhd])$') { throw "Unsupported duration '$Value' (use e.g. 5m, 1h, 1d)" }
    switch ($Matches[2]) {
        'm' { "PT$($Matches[1])M" }
        'h' { "PT$($Matches[1])H" }
        'd' { "P$($Matches[1])D" }
    }
}

function Get-IncidentConfiguration($Rule) {
    # Alert grouping: rules look back further than they run (e.g. every 5m over 1h),
    # so one event matches several runs. Grouping folds those alerts into one incident.
    $ic = $Rule.incidentConfiguration
    $g  = if ($ic) { $ic.groupingConfiguration } else { $null }
    $grouping = @{
        enabled              = [bool]($g -and $g.enabled)
        reopenClosedIncident = [bool]($g -and $g.reopenClosedIncident)
        lookbackDuration     = if ($g -and $g.lookbackDuration) { ConvertTo-IsoDuration $g.lookbackDuration } else { 'PT5H' }
        matchingMethod       = if ($g -and $g.matchingMethod) { $g.matchingMethod } else { 'AllEntities' }
        groupByEntities      = @()
        groupByAlertDetails  = @()
        groupByCustomDetails = @()
    }
    @{
        createIncident        = if ($ic -and $null -ne $ic.createIncident) { [bool]$ic.createIncident } else { $true }
        groupingConfiguration = $grouping
    }
}

$ctx = Get-AzContext
if (-not $ctx) { throw 'Run Connect-AzAccount (or use OIDC in CI) first.' }
$base = "/subscriptions/$($ctx.Subscription.Id)/resourceGroups/$ResourceGroup" +
        "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
        "/providers/Microsoft.SecurityInsights/alertRules"

foreach ($file in Get-ChildItem -Path $RulesPath -Filter *.yaml | Sort-Object Name) {
    $r = Get-Content $file.FullName -Raw | ConvertFrom-Yaml
    $props = @{
        displayName           = $r.name
        description           = $r.description
        severity              = $r.severity
        enabled               = ($r.status -eq 'Available')
        query                 = $r.query
        queryFrequency        = ConvertTo-IsoDuration $r.queryFrequency
        queryPeriod           = ConvertTo-IsoDuration $r.queryPeriod
        triggerOperator       = 'GreaterThan'
        triggerThreshold      = [int]$r.triggerThreshold
        suppressionDuration   = 'PT5H'
        suppressionEnabled    = $false
        tactics               = @($r.tactics)
        techniques            = @($r.relevantTechniques | ForEach-Object { ($_ -split '\.')[0] })
        entityMappings        = @($r.entityMappings | ForEach-Object {
            @{ entityType = $_.entityType
               fieldMappings = @($_.fieldMappings | ForEach-Object { @{ identifier = $_.identifier; columnName = $_.columnName } }) }
        })
        incidentConfiguration = (Get-IncidentConfiguration $r)
    }
    $body = @{ kind = 'Scheduled'; properties = $props } | ConvertTo-Json -Depth 10
    if ($PSCmdlet.ShouldProcess($r.name, 'PUT analytics rule')) {
        $resp = Invoke-AzRestMethod -Method PUT -Path "$base/$($r.id)?api-version=$ApiVersion" -Payload $body
        if ($resp.StatusCode -notin 200, 201) { throw "Rule '$($r.name)' failed: $($resp.StatusCode) $($resp.Content)" }
        Write-Host "Deployed: $($r.name)"
    }
}
