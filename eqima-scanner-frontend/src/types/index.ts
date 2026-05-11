export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
export type Severity   = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'

export interface Target {
  id: string
  name: string
  icon: string
  urls: string[]
  modules: string[]
}

export interface SslData {
  host: string
  grade: string
  ipAddress: string
  hasWarnings: boolean
  certSubject: string
  certIssuer: string
  certExpiry?: string
  certValidFrom?: string
  protocols: string[]
  vulnerabilities: string[]
  forwardSecrecy: boolean
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
  sslGrade?: string
  sslData?: string   // JSON string → parse vers SslData
  techData?: string  // JSON string → parse vers TechData
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