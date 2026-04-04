'use client';

import { useState, useEffect, useCallback } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
    Search, RefreshCw, MoreHorizontal, UserX, UserCheck,
    Trash2, ChevronLeft, ChevronRight, ShieldCheck, ShieldOff
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useAuthStore } from '@/store/auth';

// ─── Types ────────────────────────────────────────────────────────────────────

interface UserDto {
    id: string;
    email: string;
    username: string;
    firstName?: string;
    lastName?: string;
    isEmailVerified: boolean;
    isActive: boolean;
    isSuspended?: boolean;
    createdAt: string;
    lastLoginAt?: string;
}

interface UsersResponse {
    items: UserDto[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

type ConfirmAction =
    | { type: 'delete'; user: UserDto }
    | { type: 'suspend'; user: UserDto }
    | { type: 'activate'; user: UserDto }
    | null;

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

function UserStatusBadge({ user }: { user: UserDto }) {
    if (user.isSuspended)
        return <Badge variant="destructive" className="text-xs">Suspended</Badge>;
    if (!user.isActive)
        return <Badge variant="secondary" className="text-xs">Inactive</Badge>;
    return <Badge variant="default" className="text-xs bg-green-500/15 text-green-700 dark:text-green-400 hover:bg-green-500/20">Active</Badge>;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function UsersPage() {
    const token = useAuthStore(s => s.token);

    const [search, setSearch]                   = useState('');
    const [debouncedSearch, setDebouncedSearch] = useState('');
    const [page, setPage]                       = useState(1);
    const [data, setData]                       = useState<UsersResponse | null>(null);
    const [loading, setLoading]                 = useState(false);
    const [actionLoading, setActionLoading]     = useState<string | null>(null);
    const [error, setError]                     = useState<string | null>(null);
    const [confirm, setConfirm]                 = useState<ConfirmAction>(null);

    // Debounce search
    useEffect(() => {
        const t = setTimeout(() => { setDebouncedSearch(search); setPage(1); }, 400);
        return () => clearTimeout(t);
    }, [search]);

    const fetchUsers = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        setError(null);
        try {
            const params = new URLSearchParams({
                page: String(page),
                pageSize: String(PAGE_SIZE),
                ...(debouncedSearch && { search: debouncedSearch }),
            });
            const res = await fetch(`/api/admin/users?${params}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            setData(await res.json());
        } catch {
            setError('Failed to load users.');
        } finally {
            setLoading(false);
        }
    }, [token, page, debouncedSearch]);

    useEffect(() => { fetchUsers(); }, [fetchUsers]);

    // ─── Actions ──────────────────────────────────────────────────────────────

    const runAction = async (action: ConfirmAction) => {
        if (!action || !token) return;
        setActionLoading(action.user.id);
        setConfirm(null);

        try {
            const { type, user } = action;

            if (type === 'delete') {
                await fetch(`/api/admin/users/${user.id}`, {
                    method: 'DELETE',
                    headers: { Authorization: `Bearer ${token}` },
                });
            } else if (type === 'suspend') {
                await fetch(`/api/admin/users/${user.id}/suspend`, {
                    method: 'PATCH',
                    headers: { Authorization: `Bearer ${token}` },
                });
            } else if (type === 'activate') {
                await fetch(`/api/admin/users/${user.id}/activate`, {
                    method: 'PATCH',
                    headers: { Authorization: `Bearer ${token}` },
                });
            }

            await fetchUsers();
        } catch {
            setError('Action failed. Please try again.');
        } finally {
            setActionLoading(null);
        }
    };

    // ─── Confirm dialog content ───────────────────────────────────────────────

    const confirmContent = confirm && {
        delete: {
            title: 'Delete user?',
            description: `This will permanently deactivate ${confirm.user.email}. This action cannot be undone.`,
            label: 'Delete',
            variant: 'destructive' as const,
        },
        suspend: {
            title: 'Suspend user?',
            description: `${confirm.user.email} will lose access immediately.`,
            label: 'Suspend',
            variant: 'destructive' as const,
        },
        activate: {
            title: 'Activate user?',
            description: `${confirm.user.email} will regain full access.`,
            label: 'Activate',
            variant: 'default' as const,
        },
    }[confirm.type];

    // ─── Render ───────────────────────────────────────────────────────────────

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Users</h2>
                    <p className="text-muted-foreground">Manage registered users</p>
                </div>
                <Button variant="outline" size="sm" onClick={fetchUsers} disabled={loading}>
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                    Refresh
                </Button>
            </div>

            {/* Search */}
            <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                    placeholder="Search by email, username…"
                    className="pl-9"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                />
            </div>

            {/* Error */}
            {error && (
                <Card className="border-destructive/30 bg-destructive/5">
                    <CardContent className="pt-4">
                        <p className="text-sm text-destructive">{error}</p>
                    </CardContent>
                </Card>
            )}

            {/* Table */}
            <Card>
                <CardHeader>
                    <CardTitle className="text-sm">All Users</CardTitle>
                    <CardDescription>
                        {data ? `${data.total} total users` : '—'}
                    </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    {loading && !data ? (
                        <p className="px-6 py-10 text-center text-sm text-muted-foreground">Loading…</p>
                    ) : !data || data.items.length === 0 ? (
                        <p className="px-6 py-10 text-center text-sm text-muted-foreground">No users found</p>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                                <thead>
                                <tr className="border-b bg-muted/50">
                                    <th className="px-6 py-3 text-left font-medium text-muted-foreground">User</th>
                                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Username</th>
                                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Email</th>
                                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Joined</th>
                                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Last login</th>
                                    <th className="px-4 py-3" />
                                </tr>
                                </thead>
                                <tbody className="divide-y">
                                {data.items.map(user => (
                                    <tr key={user.id} className="hover:bg-muted/30 transition-colors">
                                        {/* Name + email */}
                                        <td className="px-6 py-3">
                                            <div>
                                                <p className="font-medium">
                                                    {user.firstName || user.lastName
                                                        ? `${user.firstName ?? ''} ${user.lastName ?? ''}`.trim()
                                                        : user.email}
                                                </p>
                                                <p className="text-xs text-muted-foreground">{user.email}</p>
                                            </div>
                                        </td>

                                        {/* Username */}
                                        <td className="px-4 py-3">
                                                <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">
                                                    {user.username}
                                                </span>
                                        </td>

                                        {/* Status */}
                                        <td className="px-4 py-3">
                                            <UserStatusBadge user={user} />
                                        </td>

                                        {/* Email verified */}
                                        <td className="px-4 py-3">
                                            {user.isEmailVerified
                                                ? <ShieldCheck className="h-4 w-4 text-green-500" />
                                                : <ShieldOff className="h-4 w-4 text-muted-foreground" />}
                                        </td>

                                        {/* Joined */}
                                        <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                                            {formatDistanceToNow(new Date(user.createdAt), { addSuffix: true })}
                                        </td>

                                        {/* Last login */}
                                        <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                                            {user.lastLoginAt
                                                ? formatDistanceToNow(new Date(user.lastLoginAt), { addSuffix: true })
                                                : '—'}
                                        </td>

                                        {/* Actions */}
                                        <td className="px-4 py-3">
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild>
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        className="h-8 w-8"
                                                        disabled={actionLoading === user.id}
                                                    >
                                                        {actionLoading === user.id
                                                            ? <RefreshCw className="h-4 w-4 animate-spin" />
                                                            : <MoreHorizontal className="h-4 w-4" />}
                                                    </Button>
                                                </DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    {user.isSuspended ? (
                                                        <DropdownMenuItem
                                                            onClick={() => setConfirm({ type: 'activate', user })}
                                                            className="text-green-600"
                                                        >
                                                            <UserCheck className="h-4 w-4 mr-2" />
                                                            Activate
                                                        </DropdownMenuItem>
                                                    ) : (
                                                        <DropdownMenuItem
                                                            onClick={() => setConfirm({ type: 'suspend', user })}
                                                            className="text-yellow-600"
                                                        >
                                                            <UserX className="h-4 w-4 mr-2" />
                                                            Suspend
                                                        </DropdownMenuItem>
                                                    )}
                                                    <DropdownMenuSeparator />
                                                    <DropdownMenuItem
                                                        onClick={() => setConfirm({ type: 'delete', user })}
                                                        className="text-destructive"
                                                    >
                                                        <Trash2 className="h-4 w-4 mr-2" />
                                                        Delete
                                                    </DropdownMenuItem>
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Pagination */}
            {data && data.totalPages > 1 && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Page {data.page} of {data.totalPages}
                    </p>
                    <div className="flex gap-2">
                        <Button
                            variant="outline" size="sm"
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1 || loading}
                        >
                            <ChevronLeft className="h-4 w-4" /> Previous
                        </Button>
                        <Button
                            variant="outline" size="sm"
                            onClick={() => setPage(p => Math.min(data.totalPages, p + 1))}
                            disabled={page === data.totalPages || loading}
                        >
                            Next <ChevronRight className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}

            {/* Confirm dialog */}
            <AlertDialog open={!!confirm} onOpenChange={open => !open && setConfirm(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>{confirmContent?.title}</AlertDialogTitle>
                        <AlertDialogDescription>{confirmContent?.description}</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                            onClick={() => runAction(confirm)}
                            className={confirm?.type === 'activate' ? '' : 'bg-destructive hover:bg-destructive/90'}
                        >
                            {confirmContent?.label}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </div>
    );
}
