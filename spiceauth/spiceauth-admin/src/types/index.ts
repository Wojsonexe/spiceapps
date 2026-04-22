// ─── Auth ────────────────────────────────────────────────────────────────────

export interface LoginRequest {
    email: string;
    password: string;
}

export interface LoginResponse {
    success: boolean;
    message: string;
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: string;
    user?: UserDto;
}

export interface UserDto {
    id: string;
    email: string;
    username: string;
    firstName?: string;
    lastName?: string;
    isEmailVerified: boolean;
    createdAt: string;
}

export interface UpdateProfileRequest {
    firstName?: string;
    lastName?: string;
    username?: string;
}

export interface ChangePasswordRequest {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
}

// ─── OAuth Clients ────────────────────────────────────────────────────────────

export interface Application {
    clientId: string;
    clientSecret?: string; // only returned on creation
    name: string;
    description?: string;
    clientType: 'Confidential' | 'Public';
    redirectUris: string[];
    allowedScopes: string[];
    requireConsent: boolean;
    requirePkce: boolean;
    isActive: boolean;
    createdAt: string;
}

export interface RegisterClientRequest {
    name: string;
    description?: string;
    clientType: 'Confidential' | 'Public';
    redirectUris: string[];
    allowedScopes: string[];
    requireConsent: boolean;
    requirePkce: boolean;
}

export interface ClientRegistrationResponse {
    clientId: string;
    clientSecret: string;
    name: string;
    redirectUris: string[];
    allowedScopes: string[];
}

// ─── Registration Approvals ───────────────────────────────────────────────────

export type RegistrationStatus = 'Pending' | 'Approved' | 'Rejected';

export interface RegistrationRequestDto {
    id: string;
    email: string;
    username: string;
    firstName?: string;
    lastName?: string;
    status: RegistrationStatus;
    createdAt: string;
    reviewedAt?: string;
    rejectionReason?: string;
}

export interface CreateRegistrationRequest {
    email: string;
    username: string;
    password: string;
    firstName?: string;
    lastName?: string;
}

export interface ApproveRegistrationRequest {
    notes?: string;
}

export interface RejectRegistrationRequest {
    reason: string;
}

export interface RegistrationStatistics {
    totalRequests: number;
    pendingRequests: number;
    approvedRequests: number;
    rejectedRequests: number;
    requestsThisWeek: number;
    requestsThisMonth: number;
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export interface DashboardStats {
    totalApplications: number;
    totalUsers: number;
    pendingRegistrations: number;
    activeTokens?: number;
}

// ─── Well-Known ───────────────────────────────────────────────────────────────

export interface OpenIdConfiguration {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    response_types_supported: string[];
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
}

// ─── Pagination ───────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    page: number;
    pageSize: number;
}

export interface ApiError {
    title?: string;
    detail?: string;
    status?: number;
    errors?: Record<string, string[]>;
}