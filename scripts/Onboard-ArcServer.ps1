<#
.SYNOPSIS
    Onboards a Windows server to Azure Arc with a locked-down agent configuration.
.DESCRIPTION
    - Certificate-based onboarding SP (no secrets in scripts or on disk)
    - Extension allowlist applied BEFORE connecting: only AMA and MDE may be installed,
      so Custom Script / Run Command cannot reach a Tier-0 server via Azure
    - Idempotent: safe to re-run; skips connect if already connected
.EXAMPLE
    .\Onboard-ArcServer.ps1 -TenantId <t> -SubscriptionId <s> -ResourceGroup rg-tier0-identity-lab `
        -ServicePrincipalId <appId> -CertificatePath C:\secure\arc-onboard.pem -Tier 0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$ServicePrincipalId,
    [Parameter(Mandatory)][ValidateScript({ Test-Path $_ })][string]$CertificatePath,
    [string]$Location = 'uksouth',
    [ValidateSet('0', '1', '2')][string]$Tier = '0',
    [string]$PrivateLinkScopeId,
    [string]$ProxyUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$log = Join-Path $env:ProgramData "ArcOnboarding\onboard-$(Get-Date -Format yyyyMMdd-HHmmss).log"
New-Item -ItemType Directory -Path (Split-Path $log) -Force | Out-Null
Start-Transcript -Path $log | Out-Null

function Invoke-AzcmAgent {
    param([string[]]$Arguments)
    & azcmagent @Arguments
    if ($LASTEXITCODE -ne 0) { throw "azcmagent $($Arguments[0]) failed (exit $LASTEXITCODE)" }
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Run as Administrator.' }

    if (-not (Get-Command azcmagent -ErrorAction SilentlyContinue)) {
        throw 'Connected Machine agent not installed. Install the signed MSI via your software distribution tool first.'
    }

    # 1. Harden the agent before it ever talks to Azure
    $allowlist = @(
        'Microsoft.Azure.Monitor/AzureMonitorWindowsAgent',
        'Microsoft.Azure.AzureDefenderForServers/MDE.Windows'
    ) -join ','
    if ($PSCmdlet.ShouldProcess('azcmagent', "Set extension allowlist: $allowlist")) {
        Invoke-AzcmAgent @('config', 'set', 'extensions.allowlist', $allowlist)
        Invoke-AzcmAgent @('config', 'set', 'guestconfiguration.enabled', 'true') # baseline audit
    }
    if ($ProxyUrl) { Invoke-AzcmAgent @('config', 'set', 'proxy.url', $ProxyUrl) }

    # 2. Idempotency check
    $state = (& azcmagent show --json | ConvertFrom-Json)
    if ($state.status -eq 'Connected') {
        Write-Host "Already connected as $($state.resourceName) in $($state.resourceGroup). Skipping connect."
    }
    elseif ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Connect to Azure Arc')) {
        $connect = @(
            'connect',
            '--service-principal-id', $ServicePrincipalId,
            '--service-principal-cert', $CertificatePath,
            '--tenant-id', $TenantId,
            '--subscription-id', $SubscriptionId,
            '--resource-group', $ResourceGroup,
            '--location', $Location,
            '--cloud', 'AzureCloud',
            '--tags', "tier=$Tier,managedBy=arc,workload=identity"
        )
        if ($PrivateLinkScopeId) { $connect += @('--private-link-scope', $PrivateLinkScopeId) }
        Invoke-AzcmAgent $connect
    }

    # 3. Verify
    Invoke-AzcmAgent @('check', '--location', $Location)
    $final = (& azcmagent show --json | ConvertFrom-Json)
    [pscustomobject]@{
        Computer      = $env:COMPUTERNAME
        Status        = $final.status
        Resource      = $final.resourceName
        ResourceGroup = $final.resourceGroup
        AgentVersion  = $final.agentVersion
        Allowlist     = $allowlist
    } | Format-List

    Write-Warning 'Remove the onboarding certificate from this host and rotate it after the onboarding wave.'
}
finally {
    Stop-Transcript | Out-Null
}
