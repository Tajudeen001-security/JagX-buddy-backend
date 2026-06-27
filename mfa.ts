import type { FastifyInstance } from 'fastify'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'
import { z } from 'zod'
import { db } from '../db'
import jwt from 'jsonwebtoken'

async function getMfaUser(req: any, reply: any) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return reply.status(401).send({ error: 'Auth required' })
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any
    req.userId = payload.sub
    req.projectId = payload.project_id
  } catch {
    return reply.status(401).send({ error: 'Invalid token' })
  }
}

export async function mfaRoutes(app: FastifyInstance) {

  // ── POST /auth/v1/mfa/enroll ── Begin MFA setup ──────────────
  app.post('/enroll', { preHandler: getMfaUser }, async (req: any, reply) => {
    const user = await db.query(
      `SELECT email FROM jagx_auth.users WHERE id = $1`,
      [req.userId]
    )
    if (!user.rows.length) return reply.status(404).send({ error: 'User not found' })

    // Check if already enrolled
    const existing = await db.query(
      `SELECT id FROM jagx_auth.mfa_factors WHERE user_id = $1 AND is_verified = TRUE`,
      [req.userId]
    )
    if (existing.rows.length) {
      return reply.status(409).send({ error: 'MFA is already enabled for this account' })
    }

    const secret = authenticator.generateSecret()
    const email = user.rows[0].email
    const issuer = 'JagX Backend'
    const otpAuthUrl = authenticator.keyuri(email, issuer, secret)

    // Save unverified factor
    await db.query(
      `INSERT INTO jagx_auth.mfa_factors (user_id, secret, is_verified)
       VALUES ($1, $2, FALSE)
       ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, is_verified = FALSE`,
      [req.userId, secret]
    )

    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl)

    return reply.send({
      secret,
      qr_code: qrCodeDataUrl,
      instructions: [
        '1. Open Google Authenticator, Authy, or any TOTP app',
        '2. Scan the QR code or enter the secret manually',
        '3. Call POST /auth/v1/mfa/verify with your 6-digit code to activate',
      ],
    })
  })

  // ── POST /auth/v1/mfa/verify ── Confirm MFA setup ─────────────
  app.post('/verify', { preHandler: getMfaUser }, async (req: any, reply) => {
    const schema = z.object({ code: z.string().length(6).regex(/^\d+$/) })
    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: '6-digit code required' })

    const factor = await db.query(
      `SELECT secret FROM jagx_auth.mfa_factors WHERE user_id = $1`,
      [req.userId]
    )

    if (!factor.rows.length) {
      return reply.status(400).send({ error: 'MFA not enrolled. Call /mfa/enroll first.' })
    }

    const isValid = authenticator.verify({
      token: body.data.code,
      secret: factor.rows[0].secret,
    })

    if (!isValid) {
      return reply.status(401).send({ error: 'Invalid code. Check your authenticator app and try again.' })
    }

    await db.query(
      `UPDATE jagx_auth.mfa_factors SET is_verified = TRUE WHERE user_id = $1`,
      [req.userId]
    )

    await db.query(
      `UPDATE jagx_auth.users SET app_metadata = app_metadata || '{"mfa_enabled": true}' WHERE id = $1`,
      [req.userId]
    )

    return reply.send({ message: 'MFA enabled successfully. Your account is now more secure.' })
  })

  // ── POST /auth/v1/mfa/challenge ── Validate MFA during login ──
  app.post('/challenge', { preHandler: getMfaUser }, async (req: any, reply) => {
    const schema = z.object({ code: z.string().length(6).regex(/^\d+$/) })
    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: '6-digit code required' })

    const factor = await db.query(
      `SELECT secret FROM jagx_auth.mfa_factors WHERE user_id = $1 AND is_verified = TRUE`,
      [req.userId]
    )

    if (!factor.rows.length) {
      return reply.status(400).send({ error: 'MFA not enabled for this account' })
    }

    const isValid = authenticator.verify({
      token: body.data.code,
      secret: factor.rows[0].secret,
    })

    if (!isValid) {
      return reply.status(401).send({ error: 'Invalid MFA code' })
    }

    return reply.send({ verified: true, message: 'MFA verified successfully' })
  })

  // ── DELETE /auth/v1/mfa/unenroll ── Disable MFA ───────────────
  app.delete('/unenroll', { preHandler: getMfaUser }, async (req: any, reply) => {
    const schema = z.object({ code: z.string().length(6).regex(/^\d+$/) })
    const body = schema.safeParse(req.body)
    if (!body.success) return reply.status(400).send({ error: 'Current MFA code required to disable' })

    const factor = await db.query(
      `SELECT secret FROM jagx_auth.mfa_factors WHERE user_id = $1 AND is_verified = TRUE`,
      [req.userId]
    )

    if (!factor.rows.length) {
      return reply.status(400).send({ error: 'MFA is not enabled' })
    }

    const isValid = authenticator.verify({
      token: body.data.code,
      secret: factor.rows[0].secret,
    })

    if (!isValid) {
      return reply.status(401).send({ error: 'Invalid MFA code. Cannot disable MFA.' })
    }

    await db.query(`DELETE FROM jagx_auth.mfa_factors WHERE user_id = $1`, [req.userId])
    await db.query(
      `UPDATE jagx_auth.users SET app_metadata = app_metadata - 'mfa_enabled' WHERE id = $1`,
      [req.userId]
    )

    return reply.send({ message: 'MFA has been disabled' })
  })

  // ── GET /auth/v1/mfa/status ───────────────────────────────────
  app.get('/status', { preHandler: getMfaUser }, async (req: any, reply) => {
    const factor = await db.query(
      `SELECT is_verified, created_at FROM jagx_auth.mfa_factors WHERE user_id = $1`,
      [req.userId]
    )

    return reply.send({
      mfa_enabled: factor.rows[0]?.is_verified || false,
      enrolled_at: factor.rows[0]?.created_at || null,
    })
  })
}
