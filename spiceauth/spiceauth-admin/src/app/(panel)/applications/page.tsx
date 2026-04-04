'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useApplications, useDeleteClient } from '@/hooks/use-applications';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import {
    Dialog, DialogContent, DialogDescription,
    DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import type { Application } from '@/types';
import { Plus, Trash2, Eye, Search } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

export default function ApplicationsPage() {
    const { data: clients, isLoading } = useApplications();
    const deleteClient = useDeleteClient();

    const [search, setSearch] = useState('');
    const [deleteTarget, setDeleteTarget] = useState<Application | null>(null);
    const [confirmId, setConfirmId] = useState('');

    const filtered = clients?.filter(c =>
        !search || c.name.toLowerCase().includes(search.toLowerCase()) ||
        c.clientId.toLowerCase().includes(search.toLowerCase())
    );

    const handleDelete = () => {
        if (!deleteTarget || confirmId !== deleteTarget.clientId) return;
        deleteClient.mutate(deleteTarget.clientId, {
            onSuccess: () => { setDeleteTarget(null); setConfirmId(''); },
        });
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight">Applications</h2>
                    <p className="text-muted-foreground">Manage OAuth 2.1 clients</p>
                </div>
                <Button asChild>
                    <Link href="/applications/new">
                        <Plus className="mr-2 h-4 w-4" /> New Application
                    </Link>
                </Button>
            </div>

            <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                    placeholder="Search applications…"
                    className="pl-9"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            <div className="rounded-md border">
                <table className="w-full text-sm">
                    <thead>
                    <tr className="border-b bg-muted/40">
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Name</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Client ID</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Type</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Scopes</th>
                        <th className="h-10 px-4 text-left font-medium text-muted-foreground">Created</th>
                        <th className="h-10 px-4 text-right font-medium text-muted-foreground">Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {isLoading
                        ? Array.from({ length: 3 }).map((_, i) => (
                            <tr key={i} className="border-b">
                                <td colSpan={6} className="px-4 py-3"><Skeleton className="h-5 w-full" /></td>
                            </tr>
                        ))
                        : filtered?.length === 0
                            ? (
                                <tr>
                                    <td colSpan={6} className="px-4 py-10 text-center text-muted-foreground">
                                        No applications found.{' '}
                                        <Link href="/applications/new" className="underline text-primary">Create one</Link>
                                    </td>
                                </tr>
                            )
                            : filtered?.map((client) => (
                                <tr key={client.clientId} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                                    <td className="px-4 py-3 font-medium">{client.name}</td>
                                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                                        {client.clientId}
                                    </td>
                                    <td className="px-4 py-3">
                                        <Badge variant="outline">{client.clientType}</Badge>
                                    </td>
                                    <td className="px-4 py-3">
                                        <div className="flex gap-1 flex-wrap">
                                            {(client.allowedScopes ?? []).slice(0, 3).map(s => (
                                                <Badge key={s} variant="secondary" className="text-xs">{s}</Badge>
                                            ))}
                                            {(client.allowedScopes?.length ?? 0) > 3 && (
                                                <Badge variant="secondary" className="text-xs">
                                                    +{client.allowedScopes.length - 3}
                                                </Badge>
                                            )}
                                        </div>
                                    </td>
                                    <td className="px-4 py-3 text-muted-foreground">
                                        {(() => {
                                            const d = new Date(client.createdAt);
                                            return isNaN(d.getTime())
                                                ? '—'
                                                : formatDistanceToNow(d, { addSuffix: true });
                                        })()}
                                    </td>

                                    <td className="px-4 py-3">
                                        <div className="flex items-center justify-end gap-2">
                                            <Button variant="ghost" size="icon" className="h-8 w-8" asChild>
                                                <Link href={`/applications/${client.clientId}`}>
                                                    <Eye className="h-4 w-4" />
                                                </Link>
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="icon"
                                                className="h-8 w-8 text-destructive hover:bg-destructive/10"
                                                onClick={() => setDeleteTarget(client)}
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>

            {/* Delete confirmation — requires typing client ID */}
            <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) { setDeleteTarget(null); setConfirmId(''); } }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Application</DialogTitle>
                        <DialogDescription>
                            This action is irreversible. Type the client ID to confirm.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-2">
                        <Label>
                            Type <code className="bg-muted px-1 py-0.5 rounded text-sm">{deleteTarget?.clientId}</code> to confirm
                        </Label>
                        <Input
                            value={confirmId}
                            onChange={(e) => setConfirmId(e.target.value)}
                            placeholder={deleteTarget?.clientId}
                            className="font-mono"
                        />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => { setDeleteTarget(null); setConfirmId(''); }}>
                            Cancel
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDelete}
                            disabled={confirmId !== deleteTarget?.clientId || deleteClient.isPending}
                        >
                            {deleteClient.isPending ? 'Deleting…' : 'Delete'}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}