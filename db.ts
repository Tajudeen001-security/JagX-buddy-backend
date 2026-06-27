// ── db.ts ─────────────────────────────────────────────────────
import { Pool } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: process.env.NODE_ENV === 'production' && process.env.DATABASE_URL?.includes('railway')
    ? { rejectUnauthorized: false }
    : false,
})

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err)
})

export const db = pool
