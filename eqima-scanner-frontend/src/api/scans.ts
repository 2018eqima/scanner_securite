import api from './client'
import { Finding, ScanSession } from '../types'

export interface SubdomainResult {
  subdomain: string
  active: boolean
  ip: string
  httpsUrl: string
  httpUrl: string
  country: string
  countryCode: string
  city: string
  org: string
}

export const scanApi = {
  list: () =>
    api.get<ScanSession[]>('/v1/scans').then(r => r.data),

  get: (id: string) =>
    api.get<ScanSession>(`/v1/scans/${id}`).then(r => r.data),

  start: (url: string, name?: string) =>
    api.post<ScanSession>('/v1/scans', { url, name }).then(r => r.data),

  findings: (id: string) =>
    api.get<Finding[]>(`/v1/scans/${id}/findings`).then(r => r.data),

  attackSurface: (id: string) =>
    api.get(`/v1/scans/${id}/attack-surface`).then(r => r.data),

  discoverSubdomains: (domain: string) =>
    api.get<SubdomainResult[]>(`/v1/subdomains/discover?domain=${encodeURIComponent(domain)}`).then(r => r.data),

  reportUrl: (id: string) =>
    `${import.meta.env.VITE_API_URL || 'https://preprod.api.scanner.eqima.org'}/v1/scans/${id}/report`,
}