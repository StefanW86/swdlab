targetScope = 'subscription'

resource rg 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-bicep-test'
  location: 'westeurope'
}
