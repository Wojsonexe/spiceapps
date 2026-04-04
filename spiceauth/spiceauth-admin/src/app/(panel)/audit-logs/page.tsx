'use client';

import { useState, useEffect, useCallback } from 'react';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
    Search, ShieldCheck, ShieldX, Trash2, Plus, LogIn, LogOut,
    Key, RefreshCw, UserX, UserCheck, ChevronLeft, ChevronRight,
    AlertTriangle, Lock
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import {useAuthStore} from "@/store/auth";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AuditEntry {
    id: string;
    action: string;
    actorEmail: string;
    actorId?: string;
    resourceType?: string;
    resourceId?: string;
    resourceName?: string;
    meta?: string;
    success: boolean;
    failureReason?: string;
    ipAddress?: string;
    timestamp: string;
}

interface AuditLogsResponse {
    items: AuditEntry[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

// ─── Action metadata ──────────────────────────────────────────────────────────

const ACTION_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
    Login:                  { label: 'Logged in',               icon: LogIn,      color: 'text-green-500' },
    Logout:                 { label: 'Logged out',              icon: LogOut,     color: 'text-muted-foreground' },
    LoginFailed:            { label: 'Login failed',            icon: AlertTriangle, color: 'text-destructive' },
    TokenIssued:            { label: 'Token issued',            icon: Key,        color: 'text-blue-500' },
    TokenRefreshed:         { label: 'Token refreshed',         icon: RefreshCw,  color: 'text-blue-400' },
    PasswordChanged:        { label: 'Password changed',        icon: Lock,       color: 'text-yellow-500' },
    RegistrationApproved:   { label: 'Approved registration',   icon: ShieldCheck,'color': 'text-green-500' },
    RegistrationRejected:   { label: 'Rejected registration',   icon: ShieldX,    color: 'text-destructive' },
    RegistrationCreated:    { label: 'Registration submitted',  icon: Plus,       color: 'text-blue-500' },
    ClientRegistered:       { label: 'Registered client',       icon: Plus,       color: 'text-blue-500' },
    ClientUpdated:          { label: 'Updated client',          icon: RefreshCw,  color: 'text-yellow-500' },
    ClientDeleted:          { label: 'Deleted client',          icon: Trash2,     color: 'text-destructive' },
    ClientSecretRotated:    { label: 'Rotated client secret',   icon: Key,        color: 'text-yellow-500' },
    ClientStatusChanged:    { label: 'Changed client status',   icon: RefreshCw,  color: 'text-blue-400' },
    UserDeleted:            { label: 'Deleted user',            icon: Trash2,     color: 'text-destructive' },
    UserSuspended:          { label: 'Suspended user',          icon: UserX,      color: 'text-destructive' },
    UserActivated:          { label: 'Activated user',          icon: UserCheck,  color: 'text-green-500' },
    ConsentGranted:         { label: 'Consent granted',         icon: ShieldCheck,color: 'text-green-500' },
    ConsentDenied:          { label: 'Consent denied',          icon: ShieldX,    color: 'text-muted-foreground' },
};

const DEFAULT_META = { label: 'Unknown action', icon: AlertTriangle, color: 'text-muted-foreground' };

// ─── Component ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

export default function AuditLogsPage() {
    const token = useAuthStore(s => s.token);

    const [search, setSearch]         = useState('');
    const [debouncedSearch, setDebouncedSearch] = useState('');
    const [page, setPage]             = useState(1);
    const [data, setData]             = useState<AuditLogsResponse | null>(null);
    const [loading, setLoading]       = useState(false);
    const [error, setError]           = useState<string | null>(null);

    // Debounce search
    useEffect(() => {
        const t = setTimeout(() => {
            setDebouncedSearch(search);
            setPage(1);
        }, 400);
        return () => clearTimeout(t);
    }, [search]);

    const fetchLogs = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        setError(null);

        try {
            const params = new URLSearchParams({
                page: String(page),
                pageSize: String(PAGE_SIZE),
                ...(debouncedSearch && { search: debouncedSearch }),
            });

            const res = await fetch(`/api/admin/audit-logs?${params}`, {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const json: AuditLogsResponse = await res.json();
            setData(json);
        } catch (e) {
            setError('Failed to load audit logs. Check API connection.');
        } finally {
            setLoading(false);
        }
    }, [token, page, debouncedSearch]);

    useEffect(() => { fetchLogs(); }, [fetchLogs]);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Audit Logs</h2>
                    <p className="text-muted-foreground">Full history of actions in SpiceAuth</p>
                </div>
                <Button variant="outline" size="sm" onClick={fetchLogs} disabled={loading}>
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                    Refresh
                </Button>
            </div>

            {/* Search */}
            <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                    placeholder="Search by actor, resource…"
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

            {/* Logs */}
            <Card>
                <CardHeader>
                    <CardTitle className="text-sm">Recent Activity</CardTitle>
                    <CardDescription>
                        {data ? `${data.total} total entries` : '—'}
                    </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                    {loading && !data ? (
                        <div className="px-6 py-10 text-center text-sm text-muted-foreground">
                            Loading…
                        </div>
                    ) : !data || data.items.length === 0 ? (
                        <p className="px-6 py-10 text-center text-sm text-muted-foreground">
                            No entries found
                        </p>
                    ) : (
                        <ul className="divide-y">
                            {data.items.map(log => {
                                const meta = ACTION_META[log.action] ?? DEFAULT_META;
                                const Icon = meta.icon;
                                return (
                                    <li key={log.id} className="flex items-start gap-4 px-6 py-4">
                                        {/* Icon */}
                                        <div className={`mt-0.5 shrink-0 ${meta.color}`}>
                                            <Icon className="h-4 w-4" />
                                        </div>

                                        {/* Content */}
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm">
                                                <span className="font-medium">{log.actorEmail}</span>
                                                {' '}{meta.label.toLowerCase()}
                                                {log.resourceName && (
                                                    <>
                                                        {' — '}
                                                        <span className="font-mono text-xs bg-muted px-1 rounded">
                                                            {log.resourceName}
                                                        </span>
                                                    </>
                                                )}
                                            </p>

                                            <div className="flex flex-wrap gap-x-3 mt-0.5">
                                                {log.meta && (
                                                    <p className="text-xs text-muted-foreground">
                                                        &quot;{log.meta}&quot;
                                                    </p>
                                                )}
                                                {log.failureReason && (
                                                    <p className="text-xs text-destructive">
                                                        {log.failureReason}
                                                    </p>
                                                )}
                                                {log.ipAddress && (
                                                    <p className="text-xs text-muted-foreground">
                                                        {log.ipAddress}
                                                    </p>
                                                )}
                                            </div>
                                        </div>

                                        {/* Badges + time */}
                                        <div className="flex items-center gap-2 shrink-0">
                                            <Badge
                                                variant={log.success ? 'secondary' : 'destructive'}
                                                className="text-xs"
                                            >
                                                {log.success ? 'OK' : 'Failed'}
                                            </Badge>
                                            <span className="text-xs text-muted-foreground whitespace-nowrap">
                                                {formatDistanceToNow(new Date(log.timestamp), { addSuffix: true })}
                                            </span>
                                        </div>
                                    </li>
                                );
                            })}
                        </ul>
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
                            variant="outline"
                            size="sm"
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            disabled={page === 1 || loading}
                        >
                            <ChevronLeft className="h-4 w-4" />
                            Previous
                        </Button>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setPage(p => Math.min(data.totalPages, p + 1))}
                            disabled={page === data.totalPages || loading}
                        >
                            Next
                            <ChevronRight className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
}
