# Hexalgon Admin Portal

Admin dashboard for managing the Hexalgon Identity & Access Management platform.

## Features

- **Onboarding** - Register new organizations/tenants
- **Login** - Authenticate as tenant admin
- **Dashboard** - Overview of clients, policies, and invitations
- **Client Management** - Register and manage OAuth2/OIDC client applications
- **Policy Management** - Create and manage user access policies
- **User Invitations** - Invite users to join the organization
- **Federation** - Create/edit/delete upstream OIDC providers, set linking behavior, and inspect linked federated identities for each provider
- **Settings** - Tenant settings and configuration

## Tech Stack

- React 18 + TypeScript
- Vite (build tool)
- TailwindCSS (styling)
- React Query (data fetching)
- React Router (routing)
- Lucide React (icons)

## Getting Started

### Prerequisites

- Node.js 18+
- npm or pnpm

### Installation

```bash
cd admin-portal
npm install
```

### Development

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.

The development server proxies `/api` requests through Vite.

Use an environment-specific proxy target depending on where the portal runs:

- host-based local dev: `http://localhost:8000`
- frontend container -> backend on host: `http://host.docker.internal:8000`
- both services in Docker Compose: use the backend service name

Recommended pattern:
- keep the proxy target environment-driven
- do not use `0.0.0.0` as the proxy target


### Build

```bash
npm run build
```

Output will be in the `dist/` folder.

## Color Theme

The portal uses a dark blue theme inspired by the Hexalgon branding:

- **Primary**: `#06b6d4` (Cyan)
- **Background**: `#0a0f1a` (Dark Navy)
- **Surface**: `#1e293b` (Navy)
- **Border**: `#334155` (Slate)

## Project Structure

```
src/
├── components/       # Reusable UI components
│   ├── ui/          # Base UI components
│   ├── Layout.tsx   # Main app layout with sidebar
│   └── Logo.tsx     # Hexalgon logo component
├── context/         # React context providers
│   └── AuthContext.tsx
├── pages/           # Route pages
│   ├── Login.tsx
│   ├── Onboarding.tsx
│   ├── Dashboard.tsx
│   ├── Clients.tsx
│   ├── Settings.tsx
│   ├── Sessions.tsx
│   ├── Policies.tsx
│   ├── Federation.tsx
│   └── Invitations.tsx
├── services/        # API client and utilities
│   ├── api.ts
│   └── utils.ts
├── App.tsx          # Root component with routing
├── main.tsx         # Entry point
└── index.css        # Global styles
```

## API Endpoints Used

### **Authentication**
- **POST** `/api/v1/authenticate/token` — Login
- **GET** `/api/v1/authenticate/sessions/all` — Get all active tenant sessions
- **GET** `/api/v1/authenticate/sessions/user/{userId}` — Get sessions for a specific user
- **DELETE** `/api/v1/authenticate/sessions/{jti}` — Revoke a single session
- **POST** `/api/v1/authenticate/sessions/bulk-revoke` — Bulk revoke sessions
- **POST** `/api/v1/authenticate/sessions/user/{userId}/revoke-all` — Revoke all sessions for a user

### **Onboarding**
- **POST** `/api/v1/onboarding/tenant/` — Create tenant and admin user

### **Users**
- **GET** `/api/v1/users` — List users
- **GET** `/api/v1/users/{userId}` — Get user details

> Placeholder client methods still exist in `src/services/api.ts` for activate/deactivate/password-reset flows, but they are **not implemented as live backend endpoints** and should not be documented as supported API yet.

### **OIDC Clients**
- **GET** `/api/v1/oidc/clients` — List clients
- **POST** `/api/v1/oidc/clients` — Create client
- **PATCH** `/api/v1/oidc/clients/{clientId}` — Update client
- **DELETE** `/api/v1/oidc/clients/{clientId}` — Delete client
- **POST** `/api/v1/oidc/clients/{clientId}/rotate-secret` — Rotate client secret

### **Access Policies**
#### **User Policies**
- **GET** `/api/v1/policies/user/{userId}` — List user-specific policies
- **POST** `/api/v1/policies/user/{userId}` — Create policy
- **PUT** `/api/v1/policies/user/{userId}/{policyId}` — Update policy
- **DELETE** `/api/v1/policies/user/{userId}/{policyId}` — Delete policy

#### **Tenant Policies**
- **GET** `/api/v1/policies/tenant` — List tenant-level policies

#### **Policy Templates**
- **GET** `/api/v1/policies/templates` — List templates
- **POST** `/api/v1/policies/templates` — Create template
- **PUT** `/api/v1/policies/templates/{templateId}` — Update template
- **DELETE** `/api/v1/policies/templates/{templateId}` — Delete template
- **POST** `/api/v1/policies/templates/assign` — Assign template to user

### **Invitations**
- **GET** `/api/v1/oidc/invitations` — List invitations
- **POST** `/api/v1/oidc/invite` — Create invitation
- **DELETE** `/api/v1/oidc/invitations/{invitationId}` — Revoke invitation

### **Federation**
- **GET** `/api/v1/federation/providers` — List trusted upstream identity providers
- **POST** `/api/v1/federation/providers` — Create provider
- **PATCH** `/api/v1/federation/providers/{providerId}` — Update provider
- **DELETE** `/api/v1/federation/providers/{providerId}` — Delete provider
- **GET** `/api/v1/federation/providers/{providerId}/links` — View linked identities for a provider

### **Tenant Settings**
- **GET** `/api/v1/tenants/me/settings` — Get tenant settings
- **PATCH** `/api/v1/tenants/me/settings` — Update tenant settings

---

### **Utility Endpoints**
- **GET** `/api/v1/{endpoint}` — Generic GET helper  
- **PATCH** `/api/v1/{endpoint}` — Generic PATCH helper  

