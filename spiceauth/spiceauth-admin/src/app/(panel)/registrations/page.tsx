'use client';

import { useState } from 'react';
import { useRegistrations, useApproveRegistration, useRejectRegistration } from '@/hooks/use-registrations';
import type { RegistrationRequestDto, RegistrationStatus } from '@/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import {
    Dialog, DialogContent, DialogDescription,
    DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Check, X, Eye, Search } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import Link from 'next/link';

const STATUS_COLORS: Record<RegistrationStatus, 'default' | 'secondary' | 'destructive'> = {
    Pending: 'default',
    Approved: 'secondary',
    Rejected: 'destructive',
};

export default function RegistrationsPage() {
    const { data: registrations, isLoading } = useRegistrations();
    const approve = useApproveRegistration();
    const reject = useRejectRegistration();

    const [filter, setFilter] = useState<RegistrationStatus | 'All'>('All');
    const [search, setSearch] = useState('');
    const [rejectTarget, setRejectTarget] = useState<RegistrationRequestDto | null>(null);
    const [rejectReason, setRejectReason] = useState('');

    const filtered = registrations?.filter((r) => {
        const matchStatus = filter === 'All' || r.status === filter;
        const q = search.toLowerCase();
        const matchSearch = !q || r.email.toLowerCase().includes(q) || r.username.toLowerCase().includes(q);
        return matchStatus && matchSearch;
    });

    const handleApprove = (id: string) => approve.mutate({ id });
    const handleReject = () => {
        if (!rejectTarget || !rejectReason.trim()) return;
        reject.mutate(
            { id: rejectTarget.id, payload: { reason: rejectReason } },
            { onSuccess: () => { setRejectTarget(null); setRejectReason(''); } }
        );
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Registrations</h2>
                    <p className="text-muted-foreground">Manage user registration requests</p>
                </div>
            </div>

            {/* Filters */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search by email or username…"
                        className="pl-9"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <Tabs value={filter} onValueChange={(v) => setFilter(v as typeof filter)}>
                    <TabsList>
                        <TabsTrigger value="All">All</TabsTrigger>
                        <TabsTrigger value="Pending">Pending</TabsTrigger>
                        <TabsTrigger value="Approved">Approved</TabsTrigger>
                        <TabsTrigger value="Rejected">Rejected</TabsTrigger>
                    </TabsList>
                </Tabs>
            </div>

            {/* Table */}
            <div className="rounded-md border">
                <table className="w-full text-sm">
                    <thead>
                    <tr className="border-b bg-muted/40">
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">User</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Email</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Status</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Submitted</th>
                        <th className="h-10 px-4 text-right font-medium text-muted-foreground">Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {isLoading
                        ? Array.from({ length: 5 }).map((_, i) => (
                            <tr key={i} className="border-b">
                                <td colSpan={5} className="px-4 py-3">
                                    <Skeleton className="h-5 w-full" />
                                </td>
                            </tr>
                        ))
                        : filtered?.length === 0
                            ? (
                                <tr>
                                    <td colSpan={5} className="px-4 py-10 text-center text-muted-foreground">
                                        No registrations found
                                    </td>
                                </tr>
                            )
                            : filtered?.map((reg) => (
                                <tr key={reg.id} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                                    <td className="px-4 py-3 font-medium">{reg.username}</td>
                                    <td className="px-4 py-3 text-muted-foreground">{reg.email}</td>
                                    <td className="px-4 py-3">
                                        <Badge variant={STATUS_COLORS[reg.status]}>{reg.status}</Badge>
                                    </td>
                                    <td className="px-4 py-3 text-muted-foreground">
                                        {formatDistanceToNow(new Date(reg.createdAt), { addSuffix: true })}
                                    </td>
                                    <td className="px-4 py-3">
                                        <div className="flex items-center justify-end gap-2">
                                            <Button variant="ghost" size="icon" className="h-8 w-8" asChild>
                                                <Link href={`/registrations/${reg.id}`}>
                                                    <Eye className="h-4 w-4" />
                                                </Link>
                                            </Button>
                                            {reg.status === 'Pending' && (
                                                <>
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        className="h-8 w-8 text-green-600 hover:text-green-700 hover:bg-green-50"
                                                        onClick={() => handleApprove(reg.id)}
                                                        disabled={approve.isPending}
                                                    >
                                                        <Check className="h-4 w-4" />
                                                    </Button>
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        className="h-8 w-8 text-destructive hover:bg-destructive/10"
                                                        onClick={() => setRejectTarget(reg)}
                                                    >
                                                        <X className="h-4 w-4" />
                                                    </Button>
                                                </>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>

            {/* Reject dialog */}
            <Dialog open={!!rejectTarget} onOpenChange={(o) => !o && setRejectTarget(null)}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Reject Registration</DialogTitle>
                        <DialogDescription>
                            Rejecting <strong>{rejectTarget?.username}</strong> ({rejectTarget?.email}).
                            A reason is required.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-2">
                        <Label htmlFor="reason">Reason</Label>
                        <Textarea
                            id="reason"
                            placeholder="Explain why this registration is being rejected…"
                            rows={3}
                            value={rejectReason}
                            onChange={(e) => setRejectReason(e.target.value)}
                        />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setRejectTarget(null)}>Cancel</Button>
                        <Button
                            variant="destructive"
                            onClick={handleReject}
                            disabled={!rejectReason.trim() || reject.isPending}
                        >
                            {reject.isPending ? 'Rejecting…' : 'Reject'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}