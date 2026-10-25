targetScope = 'subscription'

param securityContactEmail string

// Explicit sub-plan: v1 relied on the default and never stated which plan (and cost) it enabled.
resource servers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
    subPlan: 'P2' // MDE integration, vulnerability management, FIM; also covers Arc machines
  }
}

resource arm 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Arm'
  properties: {
    pricingTier: 'Standard'
  }
  dependsOn: [servers] // pricing writes conflict when run in parallel
}

// Defender for DNS is not enabled separately: it was folded into Defender for Servers P2.

resource contact 'Microsoft.Security/securityContacts@2020-01-01-preview' = {
  name: 'default'
  properties: {
    emails: securityContactEmail
    alertNotifications: {
      state: 'On'
      minimalSeverity: 'Medium'
    }
    notificationsByRole: {
      state: 'On'
      roles: ['Owner'] // valid values: Owner, Contributor, AccountAdmin, ServiceAdmin
    }
  }
}
