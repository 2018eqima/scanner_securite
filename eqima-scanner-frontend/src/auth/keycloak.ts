import Keycloak from 'keycloak-js'

const keycloak = new Keycloak({
  url:      import.meta.env.VITE_KEYCLOAK_URL || 'https://auth.eqima.org',
  realm:    'eqima',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'scanner-frontend',
})

export default keycloak