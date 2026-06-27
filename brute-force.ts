// ── brute-force.ts ────────────────────────────────────────────
import { redis } from '../redis'
import { db } from '../db'

const MAX_ATTEMPTS = 5
const LOCKOUT_MINUTES = 15

export async function checkBruteForce(projectId: string, identifier: string, ip: string): Promise<boolean> {
  const key = `lockout:${projectId}:${identifier}`
  const ipKey = `lockout:ip:${ip}`

  const [userLocked, ipLocked] = await Promise.all([
    redis.get(key),
    redis.get(ipKey),
  ])

  if (userLocked === 'locked' || ipLocked === 'locked') return true

  // Count recent failures in DB
  const result = await db.query(
    `SELECT COUNT(*) as count 
     FROM jagx_auth.login_attempts
     WHERE project_id = $1 AND identifier = $2 
       AND success = FALSE 
       AND created_at > NOW() - INTERVAL '15 minutes'`,
    [projectId, identifier]
  )

  const failureCount = parseInt(result.rows[0].count)

  if (failureCount >= MAX_ATTEMPTS) {
    // Lock in Redis for fast lookups
    await redis.setex(key, LOCKOUT_MINUTES * 60, 'locked')
    return true
  }

  return false
}

export async function recordLoginAttempt(
  projectId: string,
  identifier: string,
  ip: string,
  success: boolean
) {
  await db.query(
    `INSERT INTO jagx_auth.login_attempts (project_id, identifier, success, ip_address)
     VALUES ($1, $2, $3, $4)`,
    [projectId, identifier, success, ip]
  )

  // If success, clear lockout
  if (success) {
    await redis.del(`lockout:${projectId}:${identifier}`)
  }
}

// ── audit.ts ──────────────────────────────────────────────────
export async function createAuditLog(
  projectId: string,
  userId: string,
  action: string,
  ip: string,
  userAgent?: string,
  metadata?: Record<string, unknown>
) {
  try {
    await db.query(
      `INSERT INTO jagx_auth.audit_logs (project_id, user_id, action, ip_address, user_agent, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [projectId, userId, action, ip, userAgent || null, JSON.stringify(metadata || {})]
    )
  } catch (err) {
    // Don't fail the main request if audit logging fails
    console.error('Audit log failed:', err)
  }
}

// ── project.ts ────────────────────────────────────────────────
import { redis as r } from '../redis'

export async function getProjectFromKey(req: any) {
  const anonKey = req.headers['x-jagx-anon-key'] || req.headers['authorization']?.replace('Bearer ', '')
  const serviceKey = req.headers['x-jagx-service-key']
  const key = serviceKey || anonKey

  if (!key) return null

  // Cache project lookups in Redis (5 min TTL)
  const cached = await r.get(`project:key:${key}`)
  if (cached) return JSON.parse(cached)

  const result = await db.query(
    `SELECT * FROM jagx_meta.projects WHERE (anon_key = $1 OR service_key = $1) AND is_active = TRUE`,
    [key]
  )

  if (!result.rows.length) return null

  const project = result.rows[0]
  await r.setex(`project:key:${key}`, 300, JSON.stringify(project))
  return project
}
