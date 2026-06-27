import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { createHash, randomBytes } from 'crypto'
import { db } from '../db'
import jwt from 'jsonwebtoken'

async function requireAuth(req: any, reply: any) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return reply.status(401).send({ error: 'Auth required' })
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any
    req.userId = payload.sub
    req.projectId = payload.project_id
    req.userRole = payload.role
  } catch {
    return reply.status(401).send({ error: 'Invalid token' })
  }
}

export async function apiKeyRoutes(app: FastifyInstance) {

  // ── GET /auth/v1/keys ── List API keys ───────────────────────
  app.get('/', { preHandler: requireAuth }, async (req: any, reply) => {
    const keys = await db.query(
      `SELECT id, name, key_prefix, scopes, last_used_at, expires_at, is_active, created_at
       FROM jagx_auth.api_keys
       WHERE project_id = $1 AND user_id = $2 AND is_active = TRUE
       ORDER BY created_at DESC`,
      [req.projectId, req.userId]
    )
    return reply.send(keys.rows)
  })

  // ── POST /auth/v1/keys ── Create API key ─────────────────────
  app.post('/', { preHandler: requireAuth }, async (req: any, reply) => {
    const schema = z.object({
      name: z.string().min(1).max(100),
      scopes: z.array(z.string()).default(['read']),
      expires_in_days: z.number().min(1).max(365).optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: body.error.flatten() })

    const { name, scopes, expires_in_days } = body.data

    // Generate key: jagx_sk_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    const rawKey = `jagx_sk_${randomBytes(24).toString('hex')}`
    const keyHash = createHash('sha256').update(rawKey).digest('hex')
    const keyPrefix = rawKey.slice(0, 16) + '...'

    const expiresAt = expires_in_days
      ? new Date(Date.now() + expires_in_days * 24 * 60 * 60 * 1000).toISOString()
      : null

    const result = await db.query(
      `INSERT INTO jagx_auth.api_keys (project_id, user_id, name, key_hash, key_prefix, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, name, key_prefix, scopes, expires_at, created_at`,
      [req.projectId, req.userId, name, keyHash, keyPrefix, scopes, expiresAt]
    )

    return reply.status(201).send({
      ...result.rows[0],
      key: rawKey,
      warning: '⚠️ Save this key now — it will never be shown again',
    })
  })

  // ── DELETE /auth/v1/keys/:id ── Revoke API key ───────────────
  app.delete('/:id', { preHandler: requireAuth }, async (req: any, reply) => {
    const { id } = req.params as { id: string }

    const result = await db.query(
      `UPDATE jagx_auth.api_keys SET is_active = FALSE
       WHERE id = $1 AND project_id = $2 AND user_id = $3
       RETURNING id, name`,
      [id, req.projectId, req.userId]
    )

    if (!result.rows.length) return reply.status(404).send({ error: 'API key not found' })
    return reply.send({ message: `API key '${result.rows[0].name}' revoked` })
  })
}
