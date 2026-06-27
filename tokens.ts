// ── tokens.ts ─────────────────────────────────────────────────
import jwt from 'jsonwebtoken'

export function generateAccessToken(user: any, project: any): string {
  return jwt.sign(
    {
      sub: user.id || user.user_id,
      email: user.email,
      role: user.role || 'user',
      full_name: user.full_name,
      project_id: project.id,
      aud: 'authenticated',
      user_metadata: user.metadata || {},
      app_metadata: user.app_metadata || {},
    },
    process.env.JWT_SECRET!,
    {
      expiresIn: '1h',
      issuer: 'jagx-auth',
    }
  )
}

export function verifyAccessToken(token: string): any {
  return jwt.verify(token, process.env.JWT_SECRET!, { issuer: 'jagx-auth' })
}

export function generateRefreshToken(): string {
  const { randomBytes } = require('crypto')
  return randomBytes(48).toString('hex')
}

export function verifyRefreshToken(token: string): any {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET!, { issuer: 'jagx-auth' })
  } catch {
    return null
  }
}
