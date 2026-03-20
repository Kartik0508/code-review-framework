# Authentication & RBAC Documentation

**Project:** Implementing a Secure Framework for a Code Review Tool
**Author:** Kartik
**Date:** 20 March 2026
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Authentication System](#2-authentication-system)
3. [Role-Based Access Control](#3-role-based-access-control)
4. [API Authentication Guide](#4-api-authentication-guide)
5. [User Management](#5-user-management)
6. [Security Measures](#6-security-measures)

---

## 1. Overview

The framework uses **JWT (JSON Web Token)** based authentication combined with
**Role-Based Access Control (RBAC)** to secure all API endpoints.

**Key Points:**
- Every API endpoint requires authentication (except `/auth/login` and `/auth/register`)
- Users are assigned one of three roles: `admin`, `reviewer`, `developer`
- Each role has specific permissions — lower roles cannot access higher-role endpoints
- Tokens expire after 8 hours (configurable)
- Passwords are hashed using bcrypt — never stored in plaintext

---

## 2. Authentication System

### 2.1 How JWT Authentication Works

```
Step 1: User calls POST /auth/login with username + password
              ↓
Step 2: Backend verifies password against bcrypt hash in DB
              ↓
Step 3: Backend generates JWT token signed with SECRET_KEY
              ↓
Step 4: Token returned to user
              ↓
Step 5: User includes token in all future requests:
        Header: Authorization: Bearer <token>
              ↓
Step 6: Backend validates token on every request
              ↓
Step 7: If valid → request proceeds
        If invalid/expired → 401 Unauthorized returned
```

### 2.2 Token Structure

JWT token contains:
```json
{
  "sub": "username",
  "role": "admin",
  "exp": 1234567890
}
```

- `sub` — username (subject)
- `role` — user's role (admin/reviewer/developer)
- `exp` — expiry timestamp

### 2.3 Token Expiry

Default: **480 minutes (8 hours)**

Configurable via `.env`:
```env
ACCESS_TOKEN_EXPIRE_MINUTES=480
```

When token expires, user must login again to get a new token.

### 2.4 Auth Endpoints

| Endpoint | Method | Description | Auth Required |
|---|---|---|---|
| `/auth/register` | POST | Create new user account | No |
| `/auth/login` | POST | Login and get JWT token | No |
| `/auth/me` | GET | Get current user details | Yes |

---

## 3. Role-Based Access Control

### 3.1 Three Role Tiers

#### Developer
The base role assigned to all new registrations.
Can view scan results and issues for their projects.
Can add comments on issues.

#### Reviewer
Elevated role for security reviewers and team leads.
Can do everything a developer can plus:
- Mark issues as resolved or false positive
- Trigger scans manually
- Export compliance reports

#### Admin
Full system access.
Can do everything a reviewer can plus:
- Create and manage projects
- Create and deactivate users
- Change user roles
- Delete comments
- Access all projects regardless of ownership

### 3.2 Permission Matrix

| Permission | Developer | Reviewer | Admin |
|---|---|---|---|
| Register / Login | Yes | Yes | Yes |
| View own profile | Yes | Yes | Yes |
| View scan results | Yes | Yes | Yes |
| View issues | Yes | Yes | Yes |
| Add comment on issue | Yes | Yes | Yes |
| Delete own comment | Yes | Yes | Yes |
| Delete any comment | No | No | Yes |
| Mark issue resolved/false positive | No | Yes | Yes |
| Trigger manual scan | No | Yes | Yes |
| Export CSV report | No | Yes | Yes |
| View compliance report | No | Yes | Yes |
| Create project | No | Yes | Yes |
| Update project | No | Yes | Yes |
| Delete/deactivate project | No | No | Yes |
| View all users | No | No | Yes |
| Change user role | No | No | Yes |
| Deactivate user | No | No | Yes |

### 3.3 How Roles are Enforced in Code

Every protected endpoint uses a dependency:

```python
# Any logged-in user
_user: User = Depends(get_current_user)

# Reviewer or Admin only
_user: User = Depends(require_role("admin", "reviewer"))

# Admin only
_user: User = Depends(require_role("admin"))
```

If a user with insufficient role calls a restricted endpoint:
```json
HTTP 403 Forbidden
{
  "detail": "Insufficient permissions"
}
```

---

## 4. API Authentication Guide

### 4.1 Step 1 — Register a User

```bash
POST /auth/register
Content-Type: application/json

{
  "username": "john_dev",
  "email": "john@company.com",
  "password": "SecurePass123!"
}
```

**Note:** All new users get `developer` role by default.
An admin must manually upgrade the role if needed.

### 4.2 Step 2 — Login and Get Token

```bash
POST /auth/login
Content-Type: application/x-www-form-urlencoded

username=john_dev&password=SecurePass123!
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 4.3 Step 3 — Use Token in Requests

Include the token in the `Authorization` header of every API call:

```bash
GET /projects/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 4.4 Using Token in Swagger UI

1. Open `http://localhost:8000/docs`
2. Click the **Authorize** button (lock icon, top right)
3. Enter: `Bearer your-token-here`
4. Click **Authorize**
5. All subsequent Swagger calls will include the token automatically

### 4.5 Token Expiry Handling

If the token has expired, any API call returns:
```json
HTTP 401 Unauthorized
{
  "detail": "Token has expired"
}
```

Solution: Call `POST /auth/login` again to get a new token.

---

## 5. User Management

### 5.1 Create Admin User

New registrations default to `developer` role. To make a user admin:

**Option A — Via API (requires existing admin):**
```bash
PUT /users/{user_id}/role
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "role": "admin"
}
```

**Option B — Via Database (for first admin):**
```sql
UPDATE users SET role = 'admin' WHERE username = 'your_username';
```

### 5.2 View All Users (Admin Only)

```bash
GET /users/
Authorization: Bearer <admin-token>
```

### 5.3 Deactivate a User (Admin Only)

```bash
DELETE /users/{user_id}
Authorization: Bearer <admin-token>
```

This sets `is_active = false` — the user cannot login but their data is preserved.

### 5.4 Change User Role (Admin Only)

```bash
PUT /users/{user_id}/role
Authorization: Bearer <admin-token>

{
  "role": "reviewer"
}
```

Valid roles: `admin`, `reviewer`, `developer`

---

## 6. Security Measures

### 6.1 Password Security
- Passwords hashed with **bcrypt** (industry standard, salted)
- Plain text passwords never stored or logged
- Minimum password requirements should be enforced at registration

### 6.2 Token Security
- Tokens signed with `SECRET_KEY` from `.env` file
- Algorithm: `HS256` (HMAC-SHA256)
- Tokens expire after 8 hours
- No token revocation currently implemented (stateless JWT)

### 6.3 Webhook Security
- GitHub webhook payloads validated with **HMAC-SHA256** signature
- Signature compared using `hmac.compare_digest()` (timing-attack safe)
- Invalid signatures return `401 Unauthorized`

### 6.4 Environment Variables
- All secrets stored in `.env` file
- `.env` is in `.gitignore` — never committed to repository
- No hardcoded credentials in source code
- SonarQube confirmed: all security ratings = A

### 6.5 CORS Configuration
- CORS configured in `backend/main.py`
- Only allowed origins can call the API

---

*Document Version 1.0 — Secure Code Review Framework*
