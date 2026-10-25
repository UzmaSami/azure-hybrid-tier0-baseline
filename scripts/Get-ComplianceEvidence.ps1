#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Produces audit evidence for hybrid servers: secure score, regulatory compliance,
    and Arc-machine findings with SLA ageing. Uses Azure Resource Graph (one paged query
    per dataset) instead of per-assessment API calls.
.OUTPUTS
    CSV + JSON (machine-readable, for auditors/pipelines) and an HTML summary.
    Exit code 2 when any finding is past SLA, so a scheduled pipeline can raise a ticket.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$SubscriptionId,
    [string]$OutputPath = (Join-Path $PWD "evidence\$(Get-Date -Format yyyy-MM-dd)"),
    [hashtable]$SlaDays = @{ High = 7; Medium = 30; Low = 90 }
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-AzContext)) { throw 'Run Connect-AzAccount (or use a managed identity) first.' }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

function Invoke-ArgQuery {
    param([Parameter(Mandatory)][string]$Query)
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $p = @{ Query = $Query; Subscription = $SubscriptionId; First = 1000 }
        if ($skip) { $p.SkipToken = $skip }
        $page = Search-AzGraph @p
        foreach ($r in $page.Data) { $rows.Add($r) }
        $skip = $page.SkipToken
    } while ($skip)
    , $rows
}

$findings = Invoke-ArgQuery @'
securityresources
| where type == "microsoft.security/assessments"
| extend resourceId = tolower(tostring(properties.resourceDetails.Id))
| where resourceId contains "microsoft.hybridcompute/machines"
| project control = tostring(properties.displayName),
          machine = tostring(split(resourceId, "/")[-1]),
          severity = tostring(properties.metadata.severity),
          status = tostring(properties.status.code),
          statusChanged = todatetime(properties.status.statusChangeDate)
'@

$score = Invoke-ArgQuery @'
securityresources
| where type == "microsoft.security/securescores" and name == "ascScore"
| project subscriptionId, pct = round(toreal(properties.score.percentage) * 100, 1)
'@

$regulatory = Invoke-ArgQuery @'
securityresources
| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols"
| extend standard = tostring(split(id, "/")[6])
| summarize passed = countif(properties.state == "Passed"),
            failed = countif(properties.state == "Failed") by standard
| extend pctPassed = iff(passed + failed == 0, real(null), round(100.0 * passed / (passed + failed), 1))
'@

# NotApplicable is excluded from the denominator (v1 counted it and skewed the score)
$applicable = @($findings | Where-Object status -in 'Healthy', 'Unhealthy')
$unhealthy  = @($applicable | Where-Object status -eq 'Unhealthy')
$now = Get-Date
foreach ($f in $unhealthy) {
    $sla = $SlaDays[$f.severity]
    $age = if ($f.statusChanged) { [int]($now - [datetime]$f.statusChanged).TotalDays } else { $null }
    $f | Add-Member -NotePropertyName ageDays -NotePropertyValue $age -Force
    $f | Add-Member -NotePropertyName slaBreached -NotePropertyValue ([bool]($sla -and $age -gt $sla)) -Force
}
$breaches = @($unhealthy | Where-Object slaBreached)
$pctHealthy = if ($applicable.Count) {
    [math]::Round(100 * ($applicable.Count - $unhealthy.Count) / $applicable.Count, 1)
} else { 'n/a' }

$findings   | Export-Csv (Join-Path $OutputPath 'arc-findings.csv') -NoTypeInformation
$regulatory | Export-Csv (Join-Path $OutputPath 'regulatory-compliance.csv') -NoTypeInformation
@{ generated = $now; secureScore = $score; regulatory = $regulatory; findings = $findings } |
    ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputPath 'evidence.json') -Encoding utf8

function ConvertTo-Html5 { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }  # no HTML injection from finding text

$rowsHtml = ($unhealthy | Sort-Object slaBreached, severity -Descending | ForEach-Object {
    $cls = if ($_.slaBreached) { 'breach' } else { '' }
    "<tr class='$cls'><td>$(ConvertTo-Html5 $_.control)</td><td>$(ConvertTo-Html5 $_.machine)</td><td>$(ConvertTo-Html5 $_.severity)</td><td>$($_.ageDays)</td></tr>"
}) -join "`n"
$regHtml = ($regulatory | ForEach-Object {
    "<tr><td>$(ConvertTo-Html5 $_.standard)</td><td>$($_.passed)</td><td>$($_.failed)</td><td>$($_.pctPassed)%</td></tr>"
}) -join "`n"
$scoreText = ($score | ForEach-Object { "$($_.subscriptionId): $($_.pct)%" }) -join '; '

@"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Hybrid Security Evidence</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px}table{border-collapse:collapse;width:100%;margin:12px 0}
td,th{border:1px solid #ddd;padding:6px}th{background:#0b3d91;color:#fff}.breach{background:#fde2e2}</style></head><body>
<h1>Hybrid Security Evidence — $($now.ToString('yyyy-MM-dd'))</h1>
<p>Secure score: $scoreText</p>
<p>Arc machines: $pctHealthy% of applicable controls healthy · $($unhealthy.Count) open findings · <b>$($breaches.Count) past SLA</b></p>
<h2>Regulatory compliance</h2><table><tr><th>Standard</th><th>Passed</th><th>Failed</th><th>%</th></tr>$regHtml</table>
<h2>Open findings (SLA breaches highlighted)</h2><table><tr><th>Control</th><th>Machine</th><th>Severity</th><th>Age (days)</th></tr>$rowsHtml</table>
</body></html>
"@ | Set-Content (Join-Path $OutputPath 'summary.html') -Encoding utf8

Write-Host "Evidence written to $OutputPath"
if ($breaches.Count) { exit 2 }
