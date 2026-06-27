import { Resend } from 'resend'
import { db } from '../db'

const resend = new Resend(process.env.RESEND_API_KEY)

const FROM_EMAIL = 'JagX Backend <noreply@jagxbackend.com>'

export async function sendEmailConfirmation(project: any, user: any, email: string) {
  // Create confirmation token
  const result = await db.query(
    `INSERT INTO jagx_auth.magic_links (user_id, project_id, email, token_type)
     VALUES ($1, $2, $3, 'email_confirm')
     RETURNING token`,
    [user.id, project.id, email]
  )

  const token = result.rows[0].token
  const confirmUrl = `${process.env.APP_URL}/auth/v1/magic-link/verify?token=${token}`

  await resend.emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: `Confirm your email — ${project.name}`,
    html: emailTemplate({
      title: 'Confirm your email address',
      body: `Welcome to ${project.name}! Click the button below to confirm your email address and activate your account.`,
      buttonText: 'Confirm Email',
      buttonUrl: confirmUrl,
      footer: 'This link expires in 15 minutes. If you did not create an account, ignore this email.',
    }),
  })
}

export async function sendMagicLink(project: any, user: any, email: string) {
  // Create magic link token
  const result = await db.query(
    `INSERT INTO jagx_auth.magic_links (user_id, project_id, email, token_type)
     VALUES ($1, $2, $3, 'magic_link')
     RETURNING token`,
    [user.id, project.id, email]
  )

  const token = result.rows[0].token
  const magicUrl = `${process.env.APP_URL}/auth/v1/magic-link/verify?token=${token}`

  await resend.emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: `Your sign-in link — ${project.name}`,
    html: emailTemplate({
      title: 'Sign in to ' + project.name,
      body: `Click the button below to sign in. No password needed.`,
      buttonText: 'Sign In',
      buttonUrl: magicUrl,
      footer: 'This link expires in 15 minutes and can only be used once. If you did not request this, ignore this email.',
    }),
  })
}

export async function sendPasswordReset(project: any, user: any, email: string) {
  const result = await db.query(
    `INSERT INTO jagx_auth.magic_links (user_id, project_id, email, token_type)
     VALUES ($1, $2, $3, 'password_reset')
     RETURNING token`,
    [user.id, project.id, email]
  )

  const token = result.rows[0].token
  const resetUrl = `${process.env.APP_URL}/auth/v1/password/reset/confirm?token=${token}`

  await resend.emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: `Reset your password — ${project.name}`,
    html: emailTemplate({
      title: 'Reset your password',
      body: `You requested a password reset. Click the button below to create a new password.`,
      buttonText: 'Reset Password',
      buttonUrl: resetUrl,
      footer: 'This link expires in 15 minutes. If you did not request this, your account is still secure.',
    }),
  })
}

function emailTemplate({ title, body, buttonText, buttonUrl, footer }: {
  title: string
  body: string
  buttonText: string
  buttonUrl: string
  footer: string
}) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #222;border-radius:12px;overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:32px;text-align:center;">
              <div style="font-size:24px;font-weight:800;color:#fff;letter-spacing:-0.5px;">
                <span style="color:#6c63ff;">JagX</span> Backend
              </div>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:40px 32px;">
              <h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#fff;">${title}</h1>
              <p style="margin:0 0 32px;font-size:15px;line-height:1.6;color:#999;">${body}</p>
              <a href="${buttonUrl}" 
                 style="display:inline-block;background:linear-gradient(135deg,#6c63ff,#5a52d5);color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-size:15px;font-weight:600;">
                ${buttonText}
              </a>
              <p style="margin:24px 0 0;font-size:12px;color:#555;">
                Or copy this link: <br>
                <a href="${buttonUrl}" style="color:#6c63ff;word-break:break-all;">${buttonUrl}</a>
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:24px 32px;border-top:1px solid #1e1e1e;">
              <p style="margin:0;font-size:12px;color:#555;line-height:1.6;">${footer}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
}
