export function mappingStatusClass(status: string): string {
  if (status === 'running') return 'running'
  if (['config_error', 'disabled'].includes(status)) return 'danger'
  if (['pending_apply', 'reserved', 'deleting'].includes(status)) return 'pending'
  return 'offline'
}

export function domainStatusClass(status: string): string {
  if (['active', 'running'].includes(status)) return 'running'
  if (['error', 'blocked', 'dns_error', 'certificate_error', 'router_error'].includes(status)) return 'danger'
  return 'pending'
}

export function isDangerousClientAction(action: string): boolean {
  return new Set(['delete_mapping', 'delete_domain', 'overwrite_dns', 'reset_frp_credential']).has(action)
}

export function canCreateDomain(httpMappingCount: number): boolean {
  return Number.isInteger(httpMappingCount) && httpMappingCount > 0
}
