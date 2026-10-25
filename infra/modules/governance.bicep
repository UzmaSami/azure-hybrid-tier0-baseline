targetScope = 'subscription'

param location string
param dcrId string
param tierTagName string = 'tier'

// Built-in IDs are validated in CI, so a retired/renamed definition fails the pipeline
// instead of being silently skipped (the v1 script's `if ($windowsBaseline)` behaviour).
var builtIn = {
  windowsBaselineAudit: '/providers/Microsoft.Authorization/policyDefinitions/72650e9f-97bc-4b2a-ab5f-9781a9fcecbc'
  amaOnArcWindows: '/providers/Microsoft.Authorization/policyDefinitions/94f686d6-9a24-4e19-91f1-de937dc171a4'
  dcrAssociationWindows: '/providers/Microsoft.Authorization/policyDefinitions/eab1f514-22e3-42e3-9a1f-e1dc9199355c'
  inheritTagFromRg: '/providers/Microsoft.Authorization/policyDefinitions/ea3f2387-9b95-492a-a190-fcdc54f7b070'
  iso27001: '/providers/Microsoft.Authorization/policySetDefinitions/89c6cddc-1c73-4ac1-b19c-54d1a15a42f2'
}

var roleIds = {
  connectedMachineAdmin: 'cd570a14-e51a-42ad-bac8-bafd67325302'
  monitoringContributor: '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
  logAnalyticsContributor: '92aaf0da-9dab-42b6-94a3-d43ce8d16293'
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
}

resource baselineAudit 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'pa-win-baseline-audit'
  properties: {
    displayName: 'Windows machines (incl. Arc) must meet the Azure compute security baseline'
    policyDefinitionId: builtIn.windowsBaselineAudit
    parameters: {
      IncludeArcMachines: { value: 'true' } // default is false — v1 never actually audited the Arc DC
    }
    nonComplianceMessages: [
      { message: 'Server has drifted from the Azure Windows baseline. Follow runbook RB-02.' }
    ]
  }
}

resource amaArc 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'pa-ama-arc-windows'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Deploy Azure Monitor Agent to Windows Arc machines'
    policyDefinitionId: builtIn.amaOnArcWindows
  }
}

resource dcrAssoc 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'pa-dcr-assoc-windows'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Associate Windows machines with the Tier-0 security DCR'
    policyDefinitionId: builtIn.dcrAssociationWindows
    parameters: {
      dcrResourceId: { value: dcrId }
      resourceType: { value: 'Microsoft.Insights/dataCollectionRules' }
    }
  }
}

// Replaces the v1 imperative tagging script: tags now converge automatically.
resource tagInherit 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'pa-inherit-tier-tag'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Inherit the tier tag from the resource group'
    policyDefinitionId: builtIn.inheritTagFromRg
    parameters: {
      tagName: { value: tierTagName }
    }
  }
}

resource iso 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'pa-iso27001'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'ISO 27001 regulatory compliance (Defender for Cloud dashboard)'
    policyDefinitionId: builtIn.iso27001
  }
}

// Remediation identities — only the roles the definitions require.
resource raAma 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, amaArc.name, roleIds.connectedMachineAdmin)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.connectedMachineAdmin)
    principalId: amaArc.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raDcrMon 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, dcrAssoc.name, roleIds.monitoringContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.monitoringContributor)
    principalId: dcrAssoc.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raDcrLaw 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, dcrAssoc.name, roleIds.logAnalyticsContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.logAnalyticsContributor)
    principalId: dcrAssoc.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raTag 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, tagInherit.name, roleIds.contributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.contributor)
    principalId: tagInherit.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
