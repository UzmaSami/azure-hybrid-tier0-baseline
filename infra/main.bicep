targetScope = 'subscription'

@description('UK South keeps identity telemetry in-country.')
param location string = 'uksouth'
@allowed(['lab', 'prod'])
param environment string = 'lab'
param securityContactEmail string
param logRetentionDays int = 90
@description('Lab cost guard only. Use -1 (no cap) in prod — a capped SIEM drops security events.')
param dailyQuotaGb int = 2

var tags = {
  environment: environment
  workload: 'hybrid-tier0-baseline'
  dataClassification: 'confidential'
  owner: 'secops'
}

resource rgMonitoring 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-secops-monitoring-${environment}'
  location: location
  tags: tags
}

// Arc resources for Tier-0 servers land here. Write access via PIM only.
resource rgTier0 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-tier0-identity-${environment}'
  location: location
  tags: union(tags, { tier: '0' })
}

module monitoring 'modules/monitoring.bicep' = {
  scope: rgMonitoring
  name: 'monitoring'
  params: {
    location: location
    environment: environment
    tags: tags
    retentionDays: logRetentionDays
    dailyQuotaGb: dailyQuotaGb
  }
}

module defender 'modules/defender.bicep' = {
  name: 'defender'
  params: {
    securityContactEmail: securityContactEmail
  }
}

module governance 'modules/governance.bicep' = {
  name: 'governance'
  params: {
    location: location
    dcrId: monitoring.outputs.dcrId
  }
}

// Subscription Activity Log -> workspace (required for control-plane detections)
resource activityLog 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activitylog-to-secops-law'
  properties: {
    workspaceId: monitoring.outputs.workspaceId
    logs: [for c in ['Administrative', 'Security', 'Policy', 'Alert']: {
      category: c
      enabled: true
    }]
  }
}

output workspaceId string = monitoring.outputs.workspaceId
output tier0ResourceGroup string = rgTier0.name
