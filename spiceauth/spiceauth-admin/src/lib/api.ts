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
        // API returns { accessToken, refreshToken, expiresIn, tokenType }
        // Pick whichever field the backend actually sends:
        sessionStorage.setItem('access_token', data.accessToken);
        return data;
    },

    logout: () => {
        sessionStorage.removeItem('access_token');
        window.location.href = '/login';
    },

    getProfile: async (): Promise<UserDto> => {
        const { data } = await api.get<LoginResponse>('/api/auth/profile');
        // Profile endpoint returns same shape as login on some backends,
        // but usually returns UserDto directly — handle both:
        return (data as unknown as UserDto).email ? (data as unknown as UserDto) : data.user;
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

// ─── Well-Known ───────────────────────────────────────────────────────────────

export const wellKnownApi = {
    getOpenIdConfig: async (): Promise<OpenIdConfiguration> => {
        const { data } = await api.get<OpenIdConfiguration>('/.well-known/openid-configuration');
        return data;
    },
};