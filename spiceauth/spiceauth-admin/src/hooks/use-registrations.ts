import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { registrationApi } from '@/lib/api';
import type { ApproveRegistrationRequest, RejectRegistrationRequest } from '@/types';
import { toast } from 'sonner';
import type { AxiosError } from 'axios';

interface ApiError { message?: string; detail?: string; }

export const registrationKeys = {
    all: ['registrations'] as const,
    pending: ['registrations', 'pending'] as const,
    stats: ['registrations', 'stats'] as const,
    detail: (id: string) => ['registrations', id] as const,
};

export function useRegistrations() {
    return useQuery({
        queryKey: registrationKeys.all,
        queryFn: registrationApi.getAll,
    });
}

export function usePendingRegistrations() {
    return useQuery({
        queryKey: registrationKeys.pending,
        queryFn: registrationApi.getPending,
        refetchInterval: 30_000, // auto-refresh every 30s
    });
}

export function useRegistration(id: string) {
    return useQuery({
        queryKey: registrationKeys.detail(id),
        queryFn: () => registrationApi.getById(id),
        enabled: !!id,
    });
}

export function useRegistrationStats() {
    return useQuery({
        queryKey: registrationKeys.stats,
        queryFn: registrationApi.getStatistics,
    });
}

export function useApproveRegistration() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: ({ id, payload }: { id: string; payload?: ApproveRegistrationRequest }) =>
            registrationApi.approve(id, payload),
        onSuccess: (_, { id }) => {
            qc.invalidateQueries({ queryKey: registrationKeys.all });
            qc.invalidateQueries({ queryKey: registrationKeys.pending });
            qc.invalidateQueries({ queryKey: registrationKeys.stats });
            qc.invalidateQueries({ queryKey: registrationKeys.detail(id) });
            toast.success('Registration approved');
        },
        onError: (e: AxiosError<ApiError>) => {
            toast.error(e.response?.data?.detail || e.response?.data?.message || 'Failed to approve');
        },
    });
}

export function useRejectRegistration() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: ({ id, payload }: { id: string; payload: RejectRegistrationRequest }) =>
            registrationApi.reject(id, payload),
        onSuccess: (_, { id }) => {
            qc.invalidateQueries({ queryKey: registrationKeys.all });
            qc.invalidateQueries({ queryKey: registrationKeys.pending });
            qc.invalidateQueries({ queryKey: registrationKeys.stats });
            qc.invalidateQueries({ queryKey: registrationKeys.detail(id) });
            toast.success('Registration rejected');
        },
        onError: (e: AxiosError<ApiError>) => {
            toast.error(e.response?.data?.detail || e.response?.data?.message || 'Failed to reject');
        },
    });
}