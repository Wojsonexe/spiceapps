import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clientsApi } from '@/lib/api';
import type { RegisterClientRequest } from '@/types';
import { toast } from 'sonner';
import type { AxiosError } from 'axios';

interface ApiError { message?: string; detail?: string; }

export const clientKeys = {
    all: ['clients'] as const,
    detail: (id: string) => ['clients', id] as const,
};

export function useApplications() {
    return useQuery({
        queryKey: clientKeys.all,
        queryFn: clientsApi.getAll,
    });
}

export function useApplication(clientId: string) {
    return useQuery({
        queryKey: clientKeys.detail(clientId),
        queryFn: () => clientsApi.getById(clientId),
        enabled: !!clientId,
    });
}

export function useRegisterClient() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (payload: RegisterClientRequest) => clientsApi.register(payload),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: clientKeys.all });
            toast.success('Client registered successfully');
        },
        onError: (e: AxiosError<ApiError>) => {
            toast.error(e.response?.data?.detail || e.response?.data?.message || 'Failed to register client');
        },
    });
}

export function useDeleteClient() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (clientId: string) => clientsApi.delete(clientId),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: clientKeys.all });
            toast.success('Client deleted');
        },
        onError: (e: AxiosError<ApiError>) => {
            toast.error(e.response?.data?.detail || e.response?.data?.message || 'Failed to delete client');
        },
    });
}