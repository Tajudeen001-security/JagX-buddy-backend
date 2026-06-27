import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { db } from '../db'
import jwt from 'jsonwebtoken'
import { getProjectFromKey } from '../utils/brute-force'

async function requireAuth(req: any, reply: any) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return reply.status(401).send({ error: 'Authentication required' })
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any
    req.userId = payload.sub
    req.userRole = payload.role
    req.projectId = payload.project_id
  } catch {
    return reply.status(401).send({ error: 'Invalid or expired token' })
  }
}

async function requireAdmin(req: any, reply: any) {
  await requireAuth(req, reply)
  if (req.userRole !== 'admin' && req.userRole !== 'service_role') {
    return reply.status(403).send({ error: 'Admin access required' })
  }
}

export async function userRoutes(app: FastifyInstance) {

  // ── GET /auth/v1/user ── Get current user ────────────────────
  app.get('/', { preHandler: requireAuth }, async (req: any, reply) => {
    const user = await db.query(
      `SELECT id, email, full_name, avatar_url, role, phone, email_confirmed_at,
              last_sign_in_at, metadata, app_metadata, created_at, updated_at
       FROM jagx_auth.users WHERE id = $1`,
      [req.userId]
    )
    if (!user.rows.length) return reply.status(404).send({ error: 'User not found' })
    return reply.send(user.rows[0])
  })

  // ── PUT /auth/v1/user ── Update current user ──────────────────
  app.put('/', { preHandler: requireAuth }, async (req: any, reply) => {
    const schema = z.object({
      full_name: z.string().min(1).max(100).optional(),
      avatar_url: z.string().url().optional(),
      phone: z.string().optional(),
      metadata: z.record(z.unknown()).optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: body.error.flatten() })

    const updates = body.data
    const fields = Object.keys(updates).filter(k => updates[k as keyof typeof updates] !== undefined)
    if (fields.length === 0) return reply.status(400).send({ error: 'No fields to update' })

    const setClauses = fields.map((f, i) => `"${f}" = $${i + 2}`)
    const values = [req.userId, ...fields.map(f => updates[f as keyof typeof updates])]

    const result = await db.query(
      `UPDATE jagx_auth.users SET ${setClauses.join(', ')}, updated_at = NOW()
       WHERE id = $1
       RETURNING id, email, full_name, avatar_url, phone, role, metadata, updated_at`,
      values
    )

    return reply.send(result.rows[0])
  })

  // ── GET /auth/v1/user/sessions ── List active sessions ────────
  app.get('/sessions', { preHandler: requireAuth }, async (req: any, reply) => {
    const sessions = await db.query(
      `SELECT id, user_agent, ip_address, created_at, last_used_at, expires_at
       FROM jagx_auth.sessions
       WHERE user_id = $1 AND expires_at > NOW()
       ORDER BY last_used_at DESC`,
      [req.userId]
    )
    return reply.send(sessions.rows)
  })

  // ── DELETE /auth/v1/user/sessions/:id ── Revoke a session ─────
  app.delete('/sessions/:id', { preHandler: requireAuth }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    await db.query(
      `DELETE FROM jagx_auth.sessions WHERE id = $1 AND user_id = $2`,
      [id, req.userId]
    )
    return reply.send({ message: 'Session revoked' })
  })

  // ── DELETE /auth/v1/user/sessions ── Revoke ALL sessions ──────
  app.delete('/sessions', { preHandler: requireAuth }, async (req: any, reply) => {
    await db.query(`DELETE FROM jagx_auth.sessions WHERE user_id = $1`, [req.userId])
    return reply.send({ message: 'All sessions revoked. Please sign in again.' })
  })

  // ── GET /auth/v1/user/audit-log ── View own audit log ─────────
  app.get('/audit-log', { preHandler: requireAuth }, async (req: any, reply) => {
    const { limit = 50 } = req.query as { limit?: number }
    const logs = await db.query(
      `SELECT action, ip_address, user_agent, metadata, created_at
       FROM jagx_auth.audit_logs
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.userId, Math.min(parseInt(String(limit)), 200)]
    )
    return reply.send(logs.rows)
  })

  // ── DELETE /auth/v1/user ── Delete own account ────────────────
  app.delete('/', { preHandler: requireAuth }, async (req: any, reply) => {
    const schema = z.object({ password: z.string().min(1) })
    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Password required to delete account' })

    const bcrypt = await import('bcryptjs')
    const user = await db.query(
      `SELECT password_hash FROM jagx_auth.users WHERE id = $1`,
      [req.userId]
    )

    const isValid = user.rows[0]?.password_hash
      ? await bcrypt.compare(body.data.password, user.rows[0].password_hash)
      : false

    if (!isValid) return reply.status(401).send({ error: 'Incorrect password' })

    await db.query(`DELETE FROM jagx_auth.users WHERE id = $1`, [req.userId])
    return reply.send({ message: 'Account deleted permanently' })
  })

  // ══════════════════════════════════════════════════════════
  // ADMIN ROUTES — Manage all users in a project
  // ══════════════════════════════════════════════════════════

  // ── GET /auth/v1/user/admin/users ── List all users ──────────
  app.get('/admin/users', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { limit = 50, offset = 0, search } = req.query as any

    let sql = `
      SELECT id, email, full_name, role, email_confirmed_at, is_banned,
             last_sign_in_at, created_at, metadata, app_metadata
      FROM jagx_auth.users
      WHERE project_id = $1
    `
    const values: any[] = [req.projectId]

    if (search) {
      sql += ` AND (email ILIKE $2 OR full_name ILIKE $2)`
      values.push(`%${search}%`)
    }

    sql += ` ORDER BY created_at DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`
    values.push(Math.min(parseInt(limit), 500), parseInt(offset))

    const result = await db.query(sql, values)

    const count = await db.query(
      `SELECT COUNT(*) FROM jagx_auth.users WHERE project_id = $1`,
      [req.projectId]
    )

    reply.header('X-Total-Count', count.rows[0].count)
    return reply.send(result.rows)
  })

  // ── GET /auth/v1/user/admin/users/:id ── Get specific user ────
  app.get('/admin/users/:id', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    const user = await db.query(
      `SELECT id, email, full_name, avatar_url, role, phone, email_confirmed_at,
              is_banned, ban_reason, last_sign_in_at, metadata, app_metadata, created_at
       FROM jagx_auth.users WHERE id = $1 AND project_id = $2`,
      [id, req.projectId]
    )
    if (!user.rows.length) return reply.status(404).send({ error: 'User not found' })
    return reply.send(user.rows[0])
  })

  // ── PUT /auth/v1/user/admin/users/:id ── Update any user ──────
  app.put('/admin/users/:id', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    const schema = z.object({
      full_name: z.string().optional(),
      role: z.enum(['user', 'admin', 'moderator']).optional(),
      email_confirmed_at: z.string().datetime().optional(),
      app_metadata: z.record(z.unknown()).optional(),
      metadata: z.record(z.unknown()).optional(),
    })

    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: body.error.flatten() })

    const fields = Object.keys(body.data).filter(k => (body.data as any)[k] !== undefined)
    if (!fields.length) return reply.status(400).send({ error: 'No fields to update' })

    const setClauses = fields.map((f, i) => `"${f}" = $${i + 3}`)
    const values = [id, req.projectId, ...fields.map(f => (body.data as any)[f])]

    const result = await db.query(
      `UPDATE jagx_auth.users SET ${setClauses.join(', ')}, updated_at = NOW()
       WHERE id = $1 AND project_id = $2
       RETURNING id, email, full_name, role, app_metadata, metadata, updated_at`,
      values
    )

    if (!result.rows.length) return reply.status(404).send({ error: 'User not found' })
    return reply.send(result.rows[0])
  })

  // ── POST /auth/v1/user/admin/users/:id/ban ── Ban a user ──────
  app.post('/admin/users/:id/ban', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    const { reason } = req.body as { reason?: string }

    const result = await db.query(
      `UPDATE jagx_auth.users SET is_banned = TRUE, ban_reason = $3
       WHERE id = $1 AND project_id = $2
       RETURNING id, email, is_banned`,
      [id, req.projectId, reason || 'Banned by administrator']
    )

    if (!result.rows.length) return reply.status(404).send({ error: 'User not found' })

    // Invalidate all their sessions immediately
    await db.query(`DELETE FROM jagx_auth.sessions WHERE user_id = $1`, [id])

    return reply.send({ message: 'User banned and all sessions revoked', user: result.rows[0] })
  })

  // ── POST /auth/v1/user/admin/users/:id/unban ── Unban a user ──
  app.post('/admin/users/:id/unban', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    const result = await db.query(
      `UPDATE jagx_auth.users SET is_banned = FALSE, ban_reason = NULL
       WHERE id = $1 AND project_id = $2
       RETURNING id, email, is_banned`,
      [id, req.projectId]
    )
    if (!result.rows.length) return reply.status(404).send({ error: 'User not found' })
    return reply.send({ message: 'User unbanned successfully', user: result.rows[0] })
  })

  // ── DELETE /auth/v1/user/admin/users/:id ── Delete a user ─────
  app.delete('/admin/users/:id', { preHandler: requireAdmin }, async (req: any, reply) => {
    const { id } = req.params as { id: string }
    const result = await db.query(
      `DELETE FROM jagx_auth.users WHERE id = $1 AND project_id = $2 RETURNING id`,
      [id, req.projectId]
    )
    if (!result.rows.length) return reply.status(404).send({ error: 'User not found' })
    return reply.send({ message: 'User deleted permanently' })
  })

  // ── GET /auth/v1/user/admin/stats ── Project auth stats ───────
  app.get('/admin/stats', { preHandler: requireAdmin }, async (req: any, reply) => {
    const [totalUsers, confirmedUsers, bannedUsers, recentSignIns, recentSignups] = await Promise.all([
      db.query(`SELECT COUNT(*) FROM jagx_auth.users WHERE project_id = $1`, [req.projectId]),
      db.query(`SELECT COUNT(*) FROM jagx_auth.users WHERE project_id = $1 AND email_confirmed_at IS NOT NULL`, [req.projectId]),
      db.query(`SELECT COUNT(*) FROM jagx_auth.users WHERE project_id = $1 AND is_banned = TRUE`, [req.projectId]),
      db.query(
        `SELECT COUNT(*) FROM jagx_auth.audit_logs WHERE project_id = $1 AND action = 'sign_in' AND created_at > NOW() - INTERVAL '24 hours'`,
        [req.projectId]
      ),
      db.query(
        `SELECT COUNT(*) FROM jagx_auth.users WHERE project_id = $1 AND created_at > NOW() - INTERVAL '7 days'`,
        [req.projectId]
      ),
    ])

    return reply.send({
      total_users: parseInt(totalUsers.rows[0].count),
      confirmed_users: parseInt(confirmedUsers.rows[0].count),
      banned_users: parseInt(bannedUsers.rows[0].count),
      sign_ins_last_24h: parseInt(recentSignIns.rows[0].count),
      new_users_last_7d: parseInt(recentSignups.rows[0].count),
    })
  })
}
