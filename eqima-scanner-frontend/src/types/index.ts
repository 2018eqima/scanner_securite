export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
export type Severity   = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'

export interface Target {
  id: string
  name: string
  icon: string
  urls: string[]
  modules: string[]
}

export interface ScanSession {
  id: string
  targetId: string
  targetName: string
  targetUrl: string
  status: ScanStatus
  startedAt: string
  completedAt?: string
  progress: number
  totalFindings: number
}

export interface Finding {
  id: string
  sessionId: string
  url: string
  name: string
  description: string
  solution: string
  severity: Severity
  evidence: string
  cweid: string
  wascid: string
  detectedAt: string
}

export interface ScanEvent {
  sessionId: string
  type: 'STARTED' | 'SPIDER_PROGRESS' | 'SCAN_PROGRESS' | 'FINDING' | 'COMPLETED' | 'ERROR'
  message: string
  progress: number
  data: unknown
}