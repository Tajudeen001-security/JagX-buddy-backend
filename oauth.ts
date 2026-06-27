import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../db'
import { generateAccessToken } from '../utils/tokens'
import { createAuditLog } from '../utils/audit'
import { createHash } from 'crypto'

// ── JagX OAuth2 Server ────────────────────────────────────────
// This makes JagX a sign-in provider like Google/GitHub
// Other apps register here and use "Sign in with JagX"
// ─────────────────────────────────────────────────────────────

export async function oauthRoutes(app: FastifyInstance) {

  // ── GET /oauth/v1/authorize ──────────────────────────────────
  // Step 1: App redirects user here
  // ?client_id=xxx&redirect_uri=xxx&scope=openid email profile&state=xxx
  app.get('/authorize', async (req, reply) => {
    const { client_id, redirect_uri, scope, state, response_type } = req.query as Record<string, string>

    if (response_type !== 'code') {
      return reply.status(400).send({ error: 'Only response_type=code is supported' })
    }

    if (!client_id || !redirect_uri) {
      return reply.status(400).send({ error: 'client_id and redirect_uri are required' })
    }

    // Validate client
    const client = await db.query(
      `SELECT * FROM jagx_auth.oauth_clients WHERE client_id = $1 AND is_active = TRUE`,
      [client_id]
    )

    if (!client.rows.length) {
      return reply.status(401).send({ error: 'Unknown client_id' })
    }

    const oauthClient = client.rows[0]

    // Validate redirect URI
    if (!oauthClient.redirect_uris.includes(redirect_uri)) {
      return reply.status(400).send({ error: 'redirect_uri not registered for this client' })
    }

    // Render login page (in real app, serve HTML login form)
    // For now, return JSON that the client renders
    return reply.send({
      action: 'login_required',
      client_name: oauthClient.name,
      client_logo: oauthClient.logo_url,
      scopes: scope ? scope.split(' ') : oauthClient.scopes,
      login_url: `/oauth/v1/authorize/login?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state || ''}&scope=${scope || ''}`,
    })
  })

  // ── POST /oauth/v1/authorize/login ───────────────────────────
  // Step 2: User submits credentials, get auth code
  app.post('/authorize/login', async (req, reply) => {
    const schema = z.object({
      client_id: z.string(),
      redirect_uri: z.string().url(),
      email: z.string().email(),
      password: z.string().min(1),
      scope: z.string().optional(),
      state: z.string().optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Invalid request' })

    const { client_id, redirect_uri, email, password, scope, state } = body.data
    const bcrypt = await import('bcryptjs')

    // Validate client
    const client = await db.query(
      `SELECT * FROM jagx_auth.oauth_clients WHERE client_id = $1 AND is_active = TRUE`,
      [client_id]
    )

    if (!client.rows.length) return reply.status(401).send({ error: 'Unknown client' })

    // Get user from JagX admin project
    const adminProject = await db.query(
      `SELECT id FROM jagx_meta.projects WHERE slug = 'jagx-admin'`
    )

    const user = await db.query(
      `SELECT * FROM jagx_auth.users WHERE project_id = $1 AND email = $2`,
      [adminProject.rows[0].id, email.toLowerCase()]
    )

    if (!user.rows.length) return reply.status(401).send({ error: 'Invalid credentials' })

    const isValid = await bcrypt.compare(password, user.rows[0].password_hash)
    if (!isValid) return reply.status(401).send({ error: 'Invalid credentials' })

    // Create auth code
    const code = await db.query(
      `INSERT INTO jagx_auth.oauth_codes (client_id, user_id, scopes, redirect_uri)
       VALUES ($1, $2, $3, $4)
       RETURNING code`,
      [client_id, user.rows[0].id, scope ? scope.split(' ') : client.rows[0].scopes, redirect_uri]
    )

    await createAuditLog(adminProject.rows[0].id, user.rows[0].id, 'oauth_authorize', req.ip, req.headers['user-agent'])

    // Redirect back to the app with code
    const redirectUrl = `${redirect_uri}?code=${code.rows[0].code}${state ? `&state=${state}` : ''}`
    return reply.redirect(redirectUrl)
  })

  // ── POST /oauth/v1/token ──────────────────────────────────────
  // Step 3: App exchanges code for access token
  app.post('/token', async (req, reply) => {
    const schema = z.object({
      grant_type: z.enum(['authorization_code', 'refresh_token']),
      code: z.string().optional(),
      redirect_uri: z.string().optional(),
      client_id: z.string(),
      client_secret: z.string(),
      refresh_token: z.string().optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Invalid request' })

    const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = body.data

    // Validate client credentials
    const client = await db.query(
      `SELECT * FROM jagx_auth.oauth_clients WHERE client_id = $1 AND client_secret = $2`,
      [client_id, client_secret]
    )

    if (!client.rows.length) {
      return reply.status(401).send({ error: 'Invalid client credentials' })
    }

    if (grant_type === 'authorization_code') {
      if (!code || !redirect_uri) {
        return reply.status(400).send({ error: 'code and redirect_uri required' })
      }

      const authCode = await db.query(
        `SELECT oc.*, u.email, u.full_name, u.role, u.metadata, u.app_metadata
         FROM jagx_auth.oauth_codes oc
         JOIN jagx_auth.users u ON u.id = oc.user_id
         WHERE oc.code = $1 AND oc.client_id = $2
           AND oc.redirect_uri = $3
           AND oc.expires_at > NOW()
           AND oc.used = FALSE`,
        [code, client_id, redirect_uri]
      )

      if (!authCode.rows.length) {
        return reply.status(401).send({ error: 'Invalid, expired, or already used code' })
      }

      // Mark code as used
      await db.query(`UPDATE jagx_auth.oauth_codes SET used = TRUE WHERE code = $1`, [code])

      const adminProject = await db.query(
        `SELECT * FROM jagx_meta.projects WHERE slug = 'jagx-admin'`
      )

      const accessToken = generateAccessToken(authCode.rows[0], adminProject.rows[0])

      // Create refresh token
      const session = await db.query(
        `INSERT INTO jagx_auth.sessions (user_id, project_id, user_agent, ip_address)
         VALUES ($1, $2, $3, $4)
         RETURNING refresh_token`,
        [authCode.rows[0].user_id, adminProject.rows[0].id, req.headers['user-agent'], req.ip]
      )

      return reply.send({
        access_token: accessToken,
        refresh_token: session.rows[0].refresh_token,
        token_type: 'bearer',
        expires_in: 3600,
        scope: authCode.rows[0].scopes?.join(' '),
      })
    }

    return reply.status(400).send({ error: 'Unsupported grant_type' })
  })

  // ── GET /oauth/v1/userinfo ────────────────────────────────────
  // Step 4: App gets user profile using access token
  app.get('/userinfo', async (req, reply) => {
    const authHeader = req.headers.authorization
    if (!authHeader?.startsWith('Bearer ')) {
      return reply.status(401).send({ error: 'Bearer token required' })
    }

    const token = authHeader.slice(7)
    const jwt = await import('jsonwebtoken')

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as any

      const user = await db.query(
        `SELECT id, email, full_name, avatar_url, role, email_confirmed_at, metadata, created_at
         FROM jagx_auth.users WHERE id = $1`,
        [payload.sub]
      )

      if (!user.rows.length) return reply.status(404).send({ error: 'User not found' })

      const u = user.rows[0]
      return reply.send({
        sub: u.id,
        email: u.email,
        email_verified: !!u.email_confirmed_at,
        name: u.full_name,
        picture: u.avatar_url,
        role: u.role,
        metadata: u.metadata,
        updated_at: u.created_at,
      })
    } catch {
      return reply.status(401).send({ error: 'Invalid or expired token' })
    }
  })

  // ── GET /oauth/v1/.well-known/openid-configuration ────────────
  // OpenID Connect Discovery — apps find endpoints here automatically
  app.get('/.well-known/openid-configuration', async (req, reply) => {
    const baseUrl = process.env.APP_URL || 'http://localhost:3001'
    return reply.send({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/v1/authorize`,
      token_endpoint: `${baseUrl}/oauth/v1/token`,
      userinfo_endpoint: `${baseUrl}/oauth/v1/userinfo`,
      jwks_uri: `${baseUrl}/oauth/v1/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['HS256'],
      scopes_supported: ['openid', 'email', 'profile'],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
    })
  })

  // ── POST /oauth/v1/clients (register a new OAuth app) ────────
  app.post('/clients', async (req, reply) => {
    // Requires service_key authentication
    const serviceKey = req.headers['x-jagx-service-key']
    if (!serviceKey) return reply.status(401).send({ error: 'Service key required' })

    const project = await db.query(
      `SELECT * FROM jagx_meta.projects WHERE service_key = $1`,
      [serviceKey]
    )
    if (!project.rows.length) return reply.status(401).send({ error: 'Invalid service key' })

    const schema = z.object({
      name: z.string().min(1).max(100),
      description: z.string().optional(),
      redirect_uris: z.array(z.string().url()).min(1),
      scopes: z.array(z.string()).optional(),
      logo_url: z.string().url().optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: body.error.flatten() })

    const result = await db.query(
      `INSERT INTO jagx_auth.oauth_clients 
        (project_id, name, description, redirect_uris, scopes, logo_url)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, client_id, client_secret, name, redirect_uris, scopes, created_at`,
      [
        project.rows[0].id,
        body.data.name,
        body.data.description || null,
        body.data.redirect_uris,
        body.data.scopes || ['openid', 'email', 'profile'],
        body.data.logo_url || null,
      ]
    )

    return reply.status(201).send({
      message: 'OAuth client registered successfully',
      client: result.rows[0],
      note: 'Store client_secret securely — it will not be shown again',
    })
  })
}
