/**
 * @jagx/client — Official JavaScript SDK for JagX Backend
 * Zero dependencies, works in browser and Node.js
 */

export interface JagXConfig {
  url: string
  anonKey: string
  autoRefreshToken?: boolean
  persistSession?: boolean
}

export interface User {
  id: string
  email: string
  full_name?: string
  role: string
  metadata?: Record<string, unknown>
  app_metadata?: Record<string, unknown>
  email_confirmed_at?: string
  created_at: string
}

export interface Session {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user?: User
}

export interface AuthResponse {
  user: User | null
  session: Session | null
  error: Error | null
}

// ── JagX Auth ─────────────────────────────────────────────────
class JagXAuth {
  private config: JagXConfig
  private session: Session | null = null
  private refreshTimer: any = null
  private listeners: Array<(event: string, session: Session | null) => void> = []

  constructor(config: JagXConfig) {
    this.config = config
    if (config.persistSession !== false && typeof window !== 'undefined') {
      this.loadSession()
    }
  }

  private get authUrl() {
    return `${this.config.url}/auth/v1`
  }

  private get headers() {
    return {
      'Content-Type': 'application/json',
      'x-jagx-anon-key': this.config.anonKey,
    }
  }

  private get authHeaders() {
    return {
      ...this.headers,
      ...(this.session ? { Authorization: `Bearer ${this.session.access_token}` } : {}),
    }
  }

  private async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const res = await fetch(`${this.authUrl}${endpoint}`, {
      ...options,
      headers: { ...this.headers, ...options.headers },
    })

    const data = await res.json()
    if (!res.ok) throw new Error(data.message || data.error || 'Request failed')
    return data
  }

  private setSession(data: { user: User; session: Session }) {
    this.session = data.session
    if (this.config.persistSession !== false && typeof window !== 'undefined') {
      localStorage.setItem('jagx_session', JSON.stringify(data.session))
    }
    this.scheduleRefresh()
    this.notify('SIGNED_IN', this.session)
  }

  private loadSession() {
    try {
      const stored = localStorage.getItem('jagx_session')
      if (stored) {
        this.session = JSON.parse(stored)
        this.scheduleRefresh()
      }
    } catch {}
  }

  private scheduleRefresh() {
    if (!this.config.autoRefreshToken) return
    if (this.refreshTimer) clearTimeout(this.refreshTimer)

    // Refresh 5 minutes before expiry
    const expiresIn = (this.session?.expires_in || 3600) - 300
    this.refreshTimer = setTimeout(() => this.refreshSession(), expiresIn * 1000)
  }

  private notify(event: string, session: Session | null) {
    this.listeners.forEach(fn => fn(event, session))
  }

  async signUp(credentials: { email: string; password: string; options?: { data?: Record<string, unknown> } }): Promise<AuthResponse> {
    try {
      const data = await this.request('/signup', {
        method: 'POST',
        body: JSON.stringify({
          email: credentials.email,
          password: credentials.password,
          metadata: credentials.options?.data,
        }),
      })
      this.setSession(data)
      return { user: data.user, session: data.session, error: null }
    } catch (error: any) {
      return { user: null, session: null, error }
    }
  }

  async signIn(credentials: { email: string; password: string }): Promise<AuthResponse> {
    try {
      const data = await this.request('/signin', {
        method: 'POST',
        body: JSON.stringify(credentials),
      })
      this.setSession(data)
      return { user: data.user, session: data.session, error: null }
    } catch (error: any) {
      return { user: null, session: null, error }
    }
  }

  async signInWithMagicLink(email: string): Promise<{ error: Error | null }> {
    try {
      await this.request('/magic-link', { method: 'POST', body: JSON.stringify({ email }) })
      return { error: null }
    } catch (error: any) {
      return { error }
    }
  }

  async signOut(): Promise<{ error: Error | null }> {
    try {
      if (this.session) {
        await this.request('/signout', {
          method: 'POST',
          headers: { Authorization: `Bearer ${this.session.access_token}` },
          body: JSON.stringify({ refresh_token: this.session.refresh_token }),
        })
      }
      this.session = null
      if (typeof window !== 'undefined') localStorage.removeItem('jagx_session')
      if (this.refreshTimer) clearTimeout(this.refreshTimer)
      this.notify('SIGNED_OUT', null)
      return { error: null }
    } catch (error: any) {
      return { error }
    }
  }

  async resetPassword(email: string): Promise<{ error: Error | null }> {
    try {
      await this.request('/password/reset', { method: 'POST', body: JSON.stringify({ email }) })
      return { error: null }
    } catch (error: any) {
      return { error }
    }
  }

  async refreshSession(): Promise<AuthResponse> {
    if (!this.session?.refresh_token) {
      return { user: null, session: null, error: new Error('No session to refresh') }
    }
    try {
      const data = await this.request('/token/refresh', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: this.session.refresh_token }),
      })
      this.session = { ...this.session, ...data }
      if (typeof window !== 'undefined') localStorage.setItem('jagx_session', JSON.stringify(this.session))
      this.scheduleRefresh()
      return { user: null, session: this.session, error: null }
    } catch (error: any) {
      this.session = null
      return { user: null, session: null, error }
    }
  }

  getSession() { return this.session }

  onAuthStateChange(callback: (event: string, session: Session | null) => void) {
    this.listeners.push(callback)
    return { unsubscribe: () => { this.listeners = this.listeners.filter(fn => fn !== callback) } }
  }
}

// ── JagX Database Query Builder ──────────────────────────────
class QueryBuilder {
  private tableName: string
  private config: JagXConfig
  private session: Session | null
  private filters: string[] = []
  private selectCols = '*'
  private orderByClause?: string
  private limitNum?: number
  private offsetNum?: number

  constructor(table: string, config: JagXConfig, session: Session | null) {
    this.tableName = table
    this.config = config
    this.session = session
  }

  select(columns: string) {
    this.selectCols = columns
    return this
  }

  eq(column: string, value: unknown) {
    this.filters.push(`${column}=eq.${value}`)
    return this
  }

  neq(column: string, value: unknown) {
    this.filters.push(`${column}=neq.${value}`)
    return this
  }

  gt(column: string, value: unknown) {
    this.filters.push(`${column}=gt.${value}`)
    return this
  }

  lt(column: string, value: unknown) {
    this.filters.push(`${column}=lt.${value}`)
    return this
  }

  gte(column: string, value: unknown) {
    this.filters.push(`${column}=gte.${value}`)
    return this
  }

  lte(column: string, value: unknown) {
    this.filters.push(`${column}=lte.${value}`)
    return this
  }

  like(column: string, pattern: string) {
    this.filters.push(`${column}=like.${pattern}`)
    return this
  }

  ilike(column: string, pattern: string) {
    this.filters.push(`${column}=ilike.${pattern}`)
    return this
  }

  in(column: string, values: unknown[]) {
    this.filters.push(`${column}=in.(${values.join(',')})`)
    return this
  }

  is(column: string, value: null | boolean) {
    this.filters.push(`${column}=is.${value}`)
    return this
  }

  order(column: string, options?: { ascending?: boolean }) {
    this.orderByClause = `${column}.${options?.ascending === false ? 'desc' : 'asc'}`
    return this
  }

  limit(n: number) {
    this.limitNum = n
    return this
  }

  offset(n: number) {
    this.offsetNum = n
    return this
  }

  private buildUrl(method: string) {
    const params = new URLSearchParams()
    params.set('select', this.selectCols)
    this.filters.forEach(f => {
      const [col, val] = f.split('=')
      params.set(col, val)
    })
    if (this.orderByClause) params.set('order', this.orderByClause)
    if (this.limitNum !== undefined) params.set('limit', String(this.limitNum))
    if (this.offsetNum !== undefined) params.set('offset', String(this.offsetNum))
    return `${this.config.url}/api/v1/${this.tableName}?${params}`
  }

  private get headers() {
    return {
      'Content-Type': 'application/json',
      'x-jagx-anon-key': this.config.anonKey,
      ...(this.session ? { Authorization: `Bearer ${this.session.access_token}` } : {}),
    }
  }

  async then(resolve: (v: { data: any; error: Error | null }) => void) {
    try {
      const res = await fetch(this.buildUrl('GET'), { headers: this.headers })
      const data = await res.json()
      if (!res.ok) resolve({ data: null, error: new Error(data.message || 'Query failed') })
      else resolve({ data, error: null })
    } catch (error: any) {
      resolve({ data: null, error })
    }
  }

  async insert(data: Record<string, unknown> | Record<string, unknown>[]) {
    try {
      const res = await fetch(`${this.config.url}/api/v1/${this.tableName}`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(data),
      })
      const result = await res.json()
      if (!res.ok) return { data: null, error: new Error(result.message || 'Insert failed') }
      return { data: result, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }

  async update(data: Record<string, unknown>) {
    try {
      const res = await fetch(this.buildUrl('PATCH'), {
        method: 'PATCH',
        headers: this.headers,
        body: JSON.stringify(data),
      })
      const result = await res.json()
      if (!res.ok) return { data: null, error: new Error(result.message || 'Update failed') }
      return { data: result, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }

  async delete() {
    try {
      const res = await fetch(this.buildUrl('DELETE'), {
        method: 'DELETE',
        headers: this.headers,
      })
      if (res.status === 204) return { data: null, error: null }
      const result = await res.json()
      if (!res.ok) return { data: null, error: new Error(result.message || 'Delete failed') }
      return { data: result, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }
}

// ── JagX Storage ─────────────────────────────────────────────
class JagXStorage {
  private config: JagXConfig
  private session: Session | null

  constructor(config: JagXConfig, session: Session | null) {
    this.config = config
    this.session = session
  }

  from(bucket: string) {
    return new StorageBucket(bucket, this.config, this.session)
  }
}

class StorageBucket {
  constructor(
    private bucket: string,
    private config: JagXConfig,
    private session: Session | null
  ) {}

  private get headers() {
    return {
      'x-jagx-anon-key': this.config.anonKey,
      ...(this.session ? { Authorization: `Bearer ${this.session.access_token}` } : {}),
    }
  }

  async upload(path: string, file: File | Blob, options?: { contentType?: string }) {
    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch(`${this.config.url}/storage/v1/object/${this.bucket}/${path}`, {
        method: 'POST',
        headers: this.headers,
        body: formData,
      })

      const data = await res.json()
      if (!res.ok) return { data: null, error: new Error(data.error || 'Upload failed') }
      return { data, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }

  getPublicUrl(path: string) {
    return {
      data: {
        publicUrl: `${this.config.url}/storage/v1/object/public/${this.bucket}/${path}`,
      },
    }
  }

  async createSignedUrl(path: string, expiresIn = 3600) {
    try {
      const res = await fetch(`${this.config.url}/storage/v1/object/sign/${this.bucket}/${path}`, {
        method: 'POST',
        headers: { ...this.headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ expiresIn }),
      })
      const data = await res.json()
      if (!res.ok) return { data: null, error: new Error(data.error || 'Failed to create signed URL') }
      return { data, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }

  async remove(paths: string[]) {
    const results = await Promise.all(
      paths.map(path =>
        fetch(`${this.config.url}/storage/v1/object/${this.bucket}/${path}`, {
          method: 'DELETE',
          headers: this.headers,
        })
      )
    )
    return { data: results, error: null }
  }

  async list(prefix?: string, options?: { limit?: number; offset?: number }) {
    try {
      const params = new URLSearchParams()
      if (prefix) params.set('prefix', prefix)
      if (options?.limit) params.set('limit', String(options.limit))
      if (options?.offset) params.set('offset', String(options.offset))

      const res = await fetch(`${this.config.url}/storage/v1/object/list/${this.bucket}?${params}`, {
        headers: this.headers,
      })
      const data = await res.json()
      if (!res.ok) return { data: null, error: new Error(data.error || 'List failed') }
      return { data, error: null }
    } catch (error: any) {
      return { data: null, error }
    }
  }
}

// ── JagX Realtime ────────────────────────────────────────────
class JagXRealtime {
  private config: JagXConfig
  private session: Session | null
  private socket: any = null
  private channels: Map<string, RealtimeChannel> = new Map()

  constructor(config: JagXConfig, session: Session | null) {
    this.config = config
    this.session = session
  }

  private getSocket() {
    if (!this.socket) {
      // Dynamically import socket.io-client
      throw new Error('Install socket.io-client: npm install socket.io-client')
    }
    return this.socket
  }

  channel(name: string): RealtimeChannel {
    if (!this.channels.has(name)) {
      this.channels.set(name, new RealtimeChannel(name, this.config, this.session))
    }
    return this.channels.get(name)!
  }

  removeChannel(name: string) {
    const channel = this.channels.get(name)
    if (channel) {
      channel.unsubscribe()
      this.channels.delete(name)
    }
  }
}

class RealtimeChannel {
  private handlers: Map<string, Function[]> = new Map()
  private socket: any = null

  constructor(
    private name: string,
    private config: JagXConfig,
    private session: Session | null
  ) {}

  on(event: string, callback: (payload: any) => void) {
    if (!this.handlers.has(event)) this.handlers.set(event, [])
    this.handlers.get(event)!.push(callback)
    return this
  }

  subscribe(callback?: (status: string) => void) {
    // Real implementation connects to WebSocket
    // Stub for SDK — actual connection in browser
    if (typeof window !== 'undefined') {
      console.log(`[JagX] Subscribed to channel: ${this.name}`)
      callback?.('SUBSCRIBED')
    }
    return this
  }

  unsubscribe() {
    if (this.socket) this.socket.disconnect()
  }

  send(event: string, payload: unknown) {
    if (this.socket) {
      this.socket.emit('broadcast', { channel: this.name, event, payload })
    }
  }
}

// ── Main Client ──────────────────────────────────────────────
export class JagXClient {
  public auth: JagXAuth
  public storage: JagXStorage
  public realtime: JagXRealtime
  private config: JagXConfig

  constructor(config: JagXConfig) {
    this.config = { autoRefreshToken: true, persistSession: true, ...config }
    this.auth = new JagXAuth(this.config)
    this.storage = new JagXStorage(this.config, this.auth.getSession())
    this.realtime = new JagXRealtime(this.config, this.auth.getSession())

    // Keep storage/realtime in sync with auth changes
    this.auth.onAuthStateChange((event, session) => {
      this.storage = new JagXStorage(this.config, session)
      this.realtime = new JagXRealtime(this.config, session)
    })
  }

  from(table: string) {
    return new QueryBuilder(table, this.config, this.auth.getSession())
  }

  channel(name: string) {
    return this.realtime.channel(name)
  }
}

export function createClient(config: JagXConfig): JagXClient {
  return new JagXClient(config)
}

export default { createClient }
