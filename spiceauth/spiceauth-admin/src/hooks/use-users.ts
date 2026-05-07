import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '@/lib/api';
import { toast } from 'sonner';

export const userKeys = {
    all: ['admin-users'] as const,
    detail: (id: string) => ['admin-users', id] as const,
    roles: (id: string) => ['admin-users', id, 'roles'] as const,
    allRoles: ['admin-roles'] as const,
};

export function useUser(id: string) {
    return useQuery({
        queryKey: userKeys.detail(id),
        queryFn: () => adminApi.getUser(id),
        enabled: !!id,
    });
}

export function useAllRoles() {
    return useQuery({
        queryKey: userKeys.allRoles,
        queryFn: adminApi.getRoles,
    });
}

export function useUserRoles(userId: string) {
    return useQuery({
        queryKey: userKeys.roles(userId),
        queryFn: () => adminApi.getUserRoles(userId),
        enabled: !!userId,
    });
}

export function useAssignRole(userId: string) {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (roleName: string) => adminApi.assignRole(userId, roleName),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: userKeys.roles(userId) });
            toast.success('Role assigned');
        },
        onError: () => toast.error('Failed to assign role'),
    });
}

export function useRemoveRole(userId: string) {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (roleName: string) => adminApi.removeRole(userId, roleName),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: userKeys.roles(userId) });
            toast.success('Role removed');
        },
        onError: () => toast.error('Failed to remove role'),
    });
}
