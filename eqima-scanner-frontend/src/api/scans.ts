import api from './client'
import { Finding, ScanSession } from '../types'

export const scanApi = {
  list: () =>
    api.get<ScanSession[]>('/v1/scans').then(r => r.data),

  get: (id: string) =>
    api.get<ScanSession>(`/v1/scans/${id}`).then(r => r.data),

  start: (targetId: string, selectedUrls?: string[]) =>
    api.post<ScanSession>('/v1/scans', { targetId, selectedUrls }).then(r => r.data),

  findings: (id: string) =>
    api.get<Finding[]>(`/v1/scans/${id}/findings`).then(r => r.data),

  reportUrl: (id: string) =>
    `${import.meta.env.VITE_API_URL || 'https://api-scanner.eqima.org'}/v1/scans/${id}/report`,
}