# AuthSphere

Initial milestone for a production-style IAM backend.

## Implemented feature
- User registration (`POST /api/v1/auth/register`)
- User login (`POST /api/v1/auth/login`)
- BCrypt password hashing
- JWT access + refresh token issuance with separate secrets
- Basic account lockout after repeated login failures
- Flyway migration for the identity `users` table
- Standardized API error response

## Local development
Set environment variables if you want PostgreSQL instead of defaults:
- `DB_URL`
- `DB_USERNAME`
- `DB_PASSWORD`
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`

## Test
Run from project root:

```bash
./gradlew test
```

## Next milestone
- Refresh token rotation and persistence
- Logout and device session tracking
- Email verification flow

