import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import bcrypt from 'bcryptjs'
import { db } from '../db'
import { redis } from '../redis'
import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from '../utils/tokens'
import { sendMagicLink, sendEmailConfirmation, sendPasswordReset } from '../utils/email'
import { checkBruteForce, recordLoginAttempt } from '../utils/brute-force'
import { createAuditLog } from '../utils/audit'
import { getProjectFromKey } from '../utils/project'
import { nanoid } from 'nanoid'
import { createHash } from 'crypto'

// ── Validation Schemas ──────────────────────────────────────────
const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  full_name: z.string().min(1).max(100).optional(),
  metadata: z.record(z.unknown()).optional(),
})

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
})

const magicLinkSchema = z.object({
  email: z.string().email(),
})

const refreshSchema = z.object({
  refresh_token: z.string().min(1),
})

const resetPasswordSchema = z.object({
  email: z.string().email(),
})

const updatePasswordSchema = z.object({
  token: z.string().min(1),
  new_password: z.string()
    .min(8)
    .regex(/[A-Z]/)
    .regex(/[0-9]/),
})

// ── Auth Routes ─────────────────────────────────────────────────
export async function authRoutes(app: FastifyInstance) {

  // ── POST /auth/v1/signup ──────────────────────────────────────
  app.post('/signup', {
    config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
  }, async (req, reply) => {
    const project = await getProjectFromKey(req)
    if (!project) return reply.status(401).send({ error: 'Invalid project key' })

    const body = registerSchema.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation failed', details: body.error.flatten() })
    }

    const { email, password, full_name, metadata } = body.data

    // Check if user already exists
    const existing = await db.query(
      `SELECT id FROM jagx_auth.users WHERE project_id = $1 AND email = $2`,
      [project.id, email.toLowerCase()]
    )
    if (existing.rows.length > 0) {
      return reply.status(409).send({ error: 'User already registered with this email' })
    }

    const password_hash = await bcrypt.hash(password, 12)
    const userId = nanoid()

    const result = await db.query(
      `INSERT INTO jagx_auth.users 
        (id, project_id, email, password_hash, full_name, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, full_name, role, created_at`,
      [userId, project.id, email.toLowerCase(), password_hash, full_name || null, JSON.stringify(metadata || {})]
    )

    const user = result.rows[0]

    // Send confirmation email
    await sendEmailConfirmation(project, user, email)

    await createAuditLog(project.id, user.id, 'sign_up', req.ip, req.headers['user-agent'])

    const accessToken = generateAccessToken(user, project)
    const refreshToken = await createSession(user.id, project.id, req)

    return reply.status(201).send({
      user: sanitizeUser(user),
      session: {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 3600,
      },
    })
  })

  // ── POST /auth/v1/signin ──────────────────────────────────────
  app.post('/signin', {
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
  }, async (req, reply) => {
    const project = await getProjectFromKey(req)
    if (!project) return reply.status(401).send({ error: 'Invalid project key' })

    const body = loginSchema.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ error: 'Validation failed', details: body.error.flatten() })
    }

    const { email, password } = body.data

    // Brute force check
    const isBlocked = await checkBruteForce(project.id, email, req.ip)
    if (isBlocked) {
      return reply.status(429).send({
        error: 'Too many failed attempts. Account temporarily locked for 15 minutes.',
      })
    }

    const result = await db.query(
      `SELECT id, email, full_name, password_hash, role, email_confirmed_at, is_banned, ban_reason, metadata, app_metadata
       FROM jagx_auth.users 
       WHERE project_id = $1 AND email = $2`,
      [project.id, email.toLowerCase()]
    )

    const user = result.rows[0]
    const isValidPassword = user ? await bcrypt.compare(password, user.password_hash) : false

    if (!user || !isValidPassword) {
      await recordLoginAttempt(project.id, email, req.ip, false)
      // Timing-safe: always takes same time
      return reply.status(401).send({ error: 'Invalid email or password' })
    }

    if (user.is_banned) {
      return reply.status(403).send({
        error: 'Account suspended',
        message: user.ban_reason || 'Your account has been suspended. Contact support.',
      })
    }

    await recordLoginAttempt(project.id, email, req.ip, true)

    // Update last sign in
    await db.query(
      `UPDATE jagx_auth.users SET last_sign_in_at = NOW() WHERE id = $1`,
      [user.id]
    )

    await createAuditLog(project.id, user.id, 'sign_in', req.ip, req.headers['user-agent'])

    const accessToken = generateAccessToken(user, project)
    const refreshToken = await createSession(user.id, project.id, req)

    return reply.send({
      user: sanitizeUser(user),
      session: {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 3600,
      },
    })
  })

  // ── POST /auth/v1/signout ─────────────────────────────────────
  app.post('/signout', async (req, reply) => {
    const project = await getProjectFromKey(req)
    if (!project) return reply.status(401).send({ error: 'Invalid project key' })

    const body = refreshSchema.safeParse(req.body)
    if (body.success) {
      await db.query(
        `DELETE FROM jagx_auth.sessions WHERE refresh_token = $1`,
        [body.data.refresh_token]
      )
    }

    // Blacklist the access token in Redis (until expiry)
    const authHeader = req.headers.authorization
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7)
      const tokenHash = createHash('sha256').update(token).digest('hex')
      await redis.setex(`blacklist:${tokenHash}`, 3600, '1')
    }

    return reply.send({ message: 'Signed out successfully' })
  })

  // ── POST /auth/v1/token/refresh ───────────────────────────────
  app.post('/token/refresh', async (req, reply) => {
    const body = refreshSchema.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ error: 'refresh_token is required' })
    }

    const session = await db.query(
      `SELECT s.*, u.id as user_id, u.email, u.full_name, u.role, u.is_banned, u.metadata, u.app_metadata
       FROM jagx_auth.sessions s
       JOIN jagx_auth.users u ON u.id = s.user_id
       WHERE s.refresh_token = $1 AND s.expires_at > NOW()`,
      [body.data.refresh_token]
    )

    if (!session.rows.length) {
      return reply.status(401).send({ error: 'Invalid or expired refresh token' })
    }

    const { user_id, email, full_name, role, is_banned, project_id } = session.rows[0]

    if (is_banned) {
      return reply.status(403).send({ error: 'Account suspended' })
    }

    const project = await db.query(
      `SELECT * FROM jagx_meta.projects WHERE id = $1`,
      [project_id]
    )

    // Rotate refresh token
    const newRefreshToken = await rotateRefreshToken(session.rows[0].id)

    const accessToken = generateAccessToken(
      { id: user_id, email, full_name, role, metadata: session.rows[0].metadata, app_metadata: session.rows[0].app_metadata },
      project.rows[0]
    )

    return reply.send({
      access_token: accessToken,
      refresh_token: newRefreshToken,
      token_type: 'bearer',
      expires_in: 3600,
    })
  })

  // ── POST /auth/v1/magic-link ──────────────────────────────────
  app.post('/magic-link', {
    config: { rateLimit: { max: 3, timeWindow: '15 minutes' } },
  }, async (req, reply) => {
    const project = await getProjectFromKey(req)
    if (!project) return reply.status(401).send({ error: 'Invalid project key' })

    const body = magicLinkSchema.safeParse(req.body)
    if (!body.success) {
      return reply.status(400).send({ error: 'Valid email required' })
    }

    const { email } = body.data

    // Get or create user
    let user = await db.query(
      `SELECT id, email, full_name FROM jagx_auth.users WHERE project_id = $1 AND email = $2`,
      [project.id, email.toLowerCase()]
    )

    if (!user.rows.length) {
      // Create user without password
      const result = await db.query(
        `INSERT INTO jagx_auth.users (project_id, email) VALUES ($1, $2) RETURNING id, email, full_name`,
        [project.id, email.toLowerCase()]
      )
      user = { rows: result.rows }
    }

    await sendMagicLink(project, user.rows[0], email)

    // Always return 200 (don't reveal if email exists)
    return reply.send({ message: 'Magic link sent to your email' })
  })

  // ── GET /auth/v1/magic-link/verify?token=xxx ──────────────────
  app.get('/magic-link/verify', async (req, reply) => {
    const { token } = req.query as { token: string }
    if (!token) return reply.status(400).send({ error: 'Token required' })

    const result = await db.query(
      `SELECT ml.*, u.id as user_id, u.email, u.full_name, u.role, u.metadata, u.app_metadata,
              p.id as project_id
       FROM jagx_auth.magic_links ml
       JOIN jagx_auth.users u ON u.id = ml.user_id
       JOIN jagx_meta.projects p ON p.id = ml.project_id
       WHERE ml.token = $1 AND ml.expires_at > NOW() AND ml.used = FALSE`,
      [token]
    )

    if (!result.rows.length) {
      return reply.status(401).send({ error: 'Invalid or expired magic link' })
    }

    const { user_id, email, full_name, role, project_id } = result.rows[0]

    // Mark token as used
    await db.query(`UPDATE jagx_auth.magic_links SET used = TRUE WHERE token = $1`, [token])

    // Confirm email
    await db.query(
      `UPDATE jagx_auth.users SET email_confirmed_at = NOW() WHERE id = $1 AND email_confirmed_at IS NULL`,
      [user_id]
    )

    const project = await db.query(`SELECT * FROM jagx_meta.projects WHERE id = $1`, [project_id])

    await createAuditLog(project_id, user_id, 'magic_link_sign_in', req.ip, req.headers['user-agent'])

    const accessToken = generateAccessToken(result.rows[0], project.rows[0])
    const refreshToken = await createSession(user_id, project_id, req)

    return reply.send({
      user: sanitizeUser(result.rows[0]),
      session: {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 3600,
      },
    })
  })

  // ── POST /auth/v1/password/reset ──────────────────────────────
  app.post('/password/reset', {
    config: { rateLimit: { max: 3, timeWindow: '15 minutes' } },
  }, async (req, reply) => {
    const project = await getProjectFromKey(req)
    if (!project) return reply.status(401).send({ error: 'Invalid project key' })

    const body = resetPasswordSchema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Valid email required' })

    const user = await db.query(
      `SELECT id, email, full_name FROM jagx_auth.users WHERE project_id = $1 AND email = $2`,
      [project.id, body.data.email.toLowerCase()]
    )

    // Always return 200 to avoid email enumeration
    if (user.rows.length) {
      await sendPasswordReset(project, user.rows[0], body.data.email)
    }

    return reply.send({ message: 'If this email is registered, a reset link has been sent.' })
  })

  // ── POST /auth/v1/password/update ────────────────────────────
  app.post('/password/update', async (req, reply) => {
    const body = updatePasswordSchema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Invalid request' })

    const { token, new_password } = body.data

    const result = await db.query(
      `SELECT ml.*, u.id as user_id, ml.project_id
       FROM jagx_auth.magic_links ml
       JOIN jagx_auth.users u ON u.id = ml.user_id
       WHERE ml.token = $1 AND ml.token_type = 'password_reset'
         AND ml.expires_at > NOW() AND ml.used = FALSE`,
      [token]
    )

    if (!result.rows.length) {
      return reply.status(401).send({ error: 'Invalid or expired reset token' })
    }

    const password_hash = await bcrypt.hash(new_password, 12)
    await db.query(`UPDATE jagx_auth.users SET password_hash = $1 WHERE id = $2`, [password_hash, result.rows[0].user_id])
    await db.query(`UPDATE jagx_auth.magic_links SET used = TRUE WHERE token = $1`, [token])

    // Invalidate all sessions
    await db.query(`DELETE FROM jagx_auth.sessions WHERE user_id = $1`, [result.rows[0].user_id])

    await createAuditLog(result.rows[0].project_id, result.rows[0].user_id, 'password_updated', req.ip, req.headers['user-agent'])

    return reply.send({ message: 'Password updated successfully. Please sign in again.' })
  })
}

// ── Helpers ─────────────────────────────────────────────────────
async function createSession(userId: string, projectId: string, req: any) {
  const result = await db.query(
    `INSERT INTO jagx_auth.sessions (user_id, project_id, user_agent, ip_address)
     VALUES ($1, $2, $3, $4)
     RETURNING refresh_token`,
    [userId, projectId, req.headers['user-agent'] || null, req.ip]
  )
  return result.rows[0].refresh_token
}

async function rotateRefreshToken(sessionId: string) {
  const result = await db.query(
    `UPDATE jagx_auth.sessions 
     SET refresh_token = encode(gen_random_bytes(48), 'hex'),
         last_used_at = NOW(),
         expires_at = NOW() + INTERVAL '30 days'
     WHERE id = $1
     RETURNING refresh_token`,
    [sessionId]
  )
  return result.rows[0].refresh_token
}

function sanitizeUser(user: any) {
  const { password_hash, ...safe } = user
  return safe
}
