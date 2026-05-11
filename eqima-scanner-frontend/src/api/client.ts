import axios from 'axios'
import keycloak from '../auth/keycloak'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'https://api-scanner.eqima.org',
})

// Injecter le token Keycloak à chaque requête
api.interceptors.request.use(async config => {
  if (keycloak.isTokenExpired(30)) {
    await keycloak.updateToken(30)
  }
  if (keycloak.token) {
    config.headers.Authorization = `Bearer ${keycloak.token}`
  }
  return config
})

export default api