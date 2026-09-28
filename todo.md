# TODO: auth methods from Better Auth we don't support yet

Source: https://better-auth.com/docs/llms.txt (checked 2026-09-28).

Already supported: email + password, magic link, Google (OIDC), WhatsApp code sign-in, sign-out.

## Email & password extras

- [ ] Email verification (send link or code on sign-up, block or flag unverified users)
- [ ] Password reset (forgot-password email + reset token)
- [ ] Change password / change email for signed-in users
- [ ] Have I Been Pwned check on sign-up and password change

## Passwordless & alternative sign-in

- [ ] Email OTP (numeric code by email, for sign-in, verification and reset)
- [ ] Phone number + SMS OTP (we only have WhatsApp delivery today)
- [ ] Passkeys (WebAuthn)
- [ ] Username + password (sign in with a username instead of an email)
- [ ] Anonymous users (guest session that can later be linked to a real account)
- [ ] Google One Tap
- [ ] Sign In With Ethereum (SIWE)
- [ ] One-time token (single-use token to hand a session across apps or devices)

## Multi-factor

- [ ] Two-factor authentication: TOTP authenticator apps, OTP by email or SMS, backup codes, trusted devices

## Social providers

- [ ] Generic OAuth 2.0 / OIDC provider (config-driven, would cover most of the list below)
- [ ] Apple
- [ ] Atlassian
- [ ] Cloudflare
- [ ] Amazon Cognito
- [ ] Discord
- [ ] Dropbox
- [ ] Facebook
- [ ] Figma
- [ ] GitHub
- [ ] GitLab
- [ ] Hugging Face
- [ ] Kakao
- [ ] Kick
- [ ] LINE
- [ ] Linear
- [ ] LinkedIn
- [ ] Microsoft (Entra ID)
- [ ] Naver
- [ ] Notion
- [ ] Paybin
- [ ] PayPal
- [ ] Polar
- [ ] Railway
- [ ] Reddit
- [ ] Roblox
- [ ] Salesforce
- [ ] Slack
- [ ] Spotify
- [ ] TikTok
- [ ] Twitch
- [ ] Twitter (X)
- [ ] Vercel
- [ ] VK
- [ ] WeChat
- [ ] Zoom

## Enterprise

- [ ] Single sign-on (OIDC and SAML, per organization or domain)
- [ ] SCIM user and group provisioning
- [ ] Act as an OAuth 2.1 / OIDC provider (including MCP clients and client ID metadata documents)

## API & machine authentication

- [ ] Bearer token authentication (instead of cookies)
- [ ] JWT issuing + JWKS endpoint
- [ ] API keys
- [ ] Device authorization grant (OAuth 2.0 device flow for TVs and CLIs)
- [ ] Agent auth (identities and capabilities for AI agents)

## Session features

- [ ] Multi-session (several signed-in accounts in one browser)
- [ ] Last login method tracking
- [ ] OAuth proxy (OAuth callbacks for preview deployments)
