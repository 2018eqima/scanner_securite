import api from './client'
import { Target } from '../types'

export const targetApi = {
  list: () => api.get<Target[]>('/v1/targets').then(r => r.data),
}