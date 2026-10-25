param location string
param environment string
param tags object
param retentionDays int
param dailyQuotaGb int

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-secops-${environment}-${location}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionDays
    workspaceCapping: { dailyQuotaGb: dailyQuotaGb }
    features: {
      disableLocalAuth: true                          // no shared-key ingestion/query
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: law
  name: 'default'
  properties: {}
}

// Tier-0 focused event set. 4662 is high volume on DCs: tune the SACL, not the SIEM.
var securityXPath = 'Security!*[System[(EventID=1102 or EventID=4625 or EventID=4662 or EventID=4672 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4740 or EventID=4756 or EventID=4769 or EventID=4771)]]'

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'dcr-windows-tier0-security-${environment}'
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'tier0SecurityEvents'
          streams: ['Microsoft-SecurityEvent']
          xPathQueries: [securityXPath]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        { name: 'secopsLaw', workspaceResourceId: law.id }
      ]
    }
    dataFlows: [
      { streams: ['Microsoft-SecurityEvent'], destinations: ['secopsLaw'] }
    ]
  }
  dependsOn: [sentinel] // SecurityEvent table requires Sentinel/Defender on the workspace
}

output workspaceId string = law.id
output dcrId string = dcr.id
