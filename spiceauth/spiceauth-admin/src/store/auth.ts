import { create } from 'zustand';
import type { UserDto } from '@/types';

interface AuthState {
    user: UserDto | null;
    isAuthenticated: boolean;
    token: string | null;
    setUser: (user: UserDto | null) => void;
    setAuthenticated: (v: boolean) => void;
    setToken: (token: string | null) => void;
    logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
    user: null,
    token: typeof window !== 'undefined'
        ? sessionStorage.getItem('access_token')
        : null,
    isAuthenticated: typeof window !== 'undefined'
        ? !!sessionStorage.getItem('access_token')
        : false,

    setUser: (user) => set({ user, isAuthenticated: !!user }),
    setAuthenticated: (isAuthenticated) => set({ isAuthenticated }),
    setToken: (token) => {
        if (token) sessionStorage.setItem('access_token', token);
        else sessionStorage.removeItem('access_token');
        set({ token });
    },
    logout: () => {
        sessionStorage.removeItem('access_token');
        set({ user: null, isAuthenticated: false, token: null });
    },
}));
