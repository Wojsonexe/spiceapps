import axios, { type AxiosError } from 'axios';
import type {
    LoginRequest, LoginResponse, UserDto, UpdateProfileRequest,
    ChangePasswordRequest, Application, RegisterClientRequest,
    ClientRegistrationResponse, RegistrationRequestDto,
    ApproveRegistrationRequest, RejectRegistrationRequest,
    RegistrationStatistics, OpenIdConfiguration,
} from '@/types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://localhost:5001';

export const api = axios.create({
    baseURL: API_BASE_URL,
    headers: { 'Content-Type': 'application/json' },
    withCredentials: true, // send cookies
});

// ─── Request interceptor: attach token from cookie-backed storage ─────────────
api.interceptors.request.use((config) => {
    if (typeof window !== 'undefined') {
        const token = sessionStorage.getItem('access_token');
        if (token) config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// ─── Response interceptor: handle 401 globally ───────────────────────────────
api.interceptors.response.use(
    (res) => res,
    (error: AxiosError) => {
        if (error.response?.status === 401 && typeof window !== 'undefined') {
            sessionStorage.removeItem('access_token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const authApi = {
    login: async (payload: LoginRequest): Promise<LoginResponse> => {
        const { data } = await api.post<LoginResponse>('/api/auth/login', payload);
        if (data.access_token) sessionStorage.setItem('access_token', data.access_token);
        return data;
    },

    logout: () => {
        sessionStorage.removeItem('access_token');
        window.location.href = '/login';
    },

    getProfile: async (): Promise<UserDto> => {
        const { data } = await api.get<UserDto>('/api/auth/profile');
        return data;
    },

    updateProfile: async (payload: UpdateProfileRequest): Promise<UserDto> => {
        const { data } = await api.put<UserDto>('/api/auth/profile', payload);
        return data;
    },

    changePassword: async (payload: ChangePasswordRequest): Promise<void> => {
        await api.post('/api/auth/change-password', payload);
    },

    forgotPassword: async (email: string): Promise<void> => {
        await api.post('/api/auth/forgot-password', { email });
    },

    resetPassword: async (token: string, newPassword: string): Promise<void> => {
        await api.post('/api/auth/reset-password', { token, newPassword });
    },

    isAuthenticated: (): boolean => {
        if (typeof window === 'undefined') return false;
        return !!sessionStorage.getItem('access_token');
    },
};

// ─── OAuth Clients ────────────────────────────────────────────────────────────

export const clientsApi = {
    getAll: async (): Promise<Application[]> => {
        const { data } = await api.get<Application[]>('/api/clients');
        return data;
    },

    getById: async (clientId: string): Promise<Application> => {
        const { data } = await api.get<Application>(`/api/clients/${clientId}`);
        return data;
    },

    register: async (payload: RegisterClientRequest): Promise<ClientRegistrationResponse> => {
        const { data } = await api.post<ClientRegistrationResponse>('/api/clients/register', payload);
        return data;
    },

    delete: async (clientId: string): Promise<void> => {
        await api.delete(`/api/clients/${clientId}`);
    },
};

// ─── Registrations ────────────────────────────────────────────────────────────

export const registrationApi = {
    getAll: async (): Promise<RegistrationRequestDto[]> => {
        const { data } = await api.get<RegistrationRequestDto[]>('/api/registration');
        return data;
    },

    getPending: async (): Promise<RegistrationRequestDto[]> => {
        const { data } = await api.get<RegistrationRequestDto[]>('/api/registration/pending');
        return data;
    },

    getById: async (id: string): Promise<RegistrationRequestDto> => {
        const { data } = await api.get<RegistrationRequestDto>(`/api/registration/${id}`);
        return data;
    },

    approve: async (id: string, payload?: ApproveRegistrationRequest): Promise<void> => {
        await api.post(`/api/registration/${id}/approve`, payload ?? {});
    },

    reject: async (id: string, payload: RejectRegistrationRequest): Promise<void> => {
        await api.post(`/api/registration/${id}/reject`, payload);
    },

    getStatistics: async (): Promise<RegistrationStatistics> => {
        const { data } = await api.get<RegistrationStatistics>('/api/registration/statistics');
        return data;
    },
};

// ─── Admin ────────────────────────────────────────────────────────────────────

export const adminApi = {
    getUsers: async (page = 1, pageSize = 50, search?: string) => {
        const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
        if (search) params.set('search', search);
        const { data } = await api.get(`/api/admin/users?${params}`);
        return data;
    },

    getUser: async (id: string) => {
        const { data } = await api.get(`/api/admin/users/${id}`);
        return data;
    },

    getRoles: async (): Promise<{ id: string; name: string; description: string | null; isSystemRole: boolean }[]> => {
        const { data } = await api.get('/api/admin/roles');
        return data;
    },

    getUserRoles: async (userId: string): Promise<{ id: string; name: string; description: string | null; assignedAt: string }[]> => {
        const { data } = await api.get(`/api/admin/users/${userId}/roles`);
        return data;
    },

    assignRole: async (userId: string, roleName: string): Promise<void> => {
        await api.post(`/api/admin/users/${userId}/roles/${encodeURIComponent(roleName)}`);
    },

    removeRole: async (userId: string, roleName: string): Promise<void> => {
        await api.delete(`/api/admin/users/${userId}/roles/${encodeURIComponent(roleName)}`);
    },

    suspendUser: async (userId: string): Promise<void> => {
        await api.patch(`/api/admin/users/${userId}/suspend`);
    },

    activateUser: async (userId: string): Promise<void> => {
        await api.patch(`/api/admin/users/${userId}/activate`);
    },
};

// ─── Well-Known ───────────────────────────────────────────────────────────────

export const wellKnownApi = {
    getOpenIdConfig: async (): Promise<OpenIdConfiguration> => {
        const { data } = await api.get<OpenIdConfiguration>('/.well-known/openid-configuration');
        return data;
    },
};