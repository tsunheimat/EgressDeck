export type PageName = 'overview' | 'proxies' | 'subscriptions' | 'devices' | 'rules' | 'infrastructure' | 'activity'
export interface NavigationTarget {
  page: PageName
  resource?: 'policy' | 'rule_set' | 'device_group'
  id?: string
  ruleId?: string
}
const pages = new Set<PageName>(['overview', 'proxies', 'subscriptions', 'devices', 'rules', 'infrastructure', 'activity'])

export function navigationHref(target: NavigationTarget): string {
  const query = new URLSearchParams()
  if (target.resource) query.set('resource', target.resource)
  if (target.id) query.set('id', target.id)
  if (target.ruleId) query.set('rule', target.ruleId)
  return `#/${target.page}${query.size ? `?${query}` : ''}`
}

export function readNavigationTarget(hash = typeof window === 'undefined' ? '' : window.location.hash): NavigationTarget {
  const [path = '', search = ''] = hash.replace(/^#\/?/, '').split('?')
  const page = pages.has(path as PageName) ? path as PageName : 'overview'
  const query = new URLSearchParams(search)
  const resource = query.get('resource')
  return { page, resource: resource === 'policy' || resource === 'rule_set' || resource === 'device_group' ? resource : undefined, id: query.get('id') ?? undefined, ruleId: query.get('rule') ?? undefined }
}

export function subscribeNavigationTarget(listener: (target: NavigationTarget) => void): () => void {
  if (typeof window === 'undefined') return () => {}
  const onChange = () => listener(readNavigationTarget())
  window.addEventListener('hashchange', onChange)
  return () => window.removeEventListener('hashchange', onChange)
}
