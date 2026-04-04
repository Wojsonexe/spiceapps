'use client';

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useRegistration, useApproveRegistration, useRejectRegistration } from '@/hooks/use-registrations';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Skeleton } from '@/components/ui/skeleton';
import { ArrowLeft, Check, X } from 'lucide-react';
import { format } from 'date-fns';
import type { RegistrationStatus } from '@/types';

const STATUS_COLORS: Record<RegistrationStatus, 'default' | 'secondary' | 'destructive'> = {
    Pending: 'default',
    Approved: 'secondary',
    Rejected: 'destructive',
};

export default function RegistrationDetailPage() {
    const { id } = useParams<{ id: string }>();
    const router = useRouter();
    const { data: reg, isLoading } = useRegistration(id);
    const approve = useApproveRegistration();
    const reject = useRejectRegistration();

    const [rejectReason, setRejectReason] = useState('');
    const [showRejectForm, setShowRejectForm] = useState(false);

    const handleApprove = () => {
        approve.mutate({ id }, { onSuccess: () => router.push('/registrations') });
    };

    const handleReject = () => {
        if (!rejectReason.trim()) return;
        reject.mutate(
            { id, payload: { reason: rejectReason } },
            { onSuccess: () => router.push('/registrations') }
        );
    };

    if (isLoading) return (
        <div className="space-y-4 max-w-xl">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-40 w-full" />
        </div>
    );

    if (!reg) return <p className="text-muted-foreground">Registration not found.</p>;

    return (
        <div className="max-w-xl space-y-6">
            <Button variant="ghost" size="sm" onClick={() => router.back()} className="-ml-2">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
            </Button>

            <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold">{reg.username}</h2>
                <Badge variant={STATUS_COLORS[reg.status]}>{reg.status}</Badge>
            </div>

            <Card>
                <CardHeader><CardTitle className="text-sm">Details</CardTitle></CardHeader>
                <CardContent className="space-y-3 text-sm">
                    <Row label="Email" value={reg.email} />
                    <Row label="Username" value={reg.username} />
                    {reg.firstName && <Row label="First name" value={reg.firstName} />}
                    {reg.lastName && <Row label="Last name" value={reg.lastName} />}
                    <Row label="Submitted" value={format(new Date(reg.createdAt), 'PPP p')} />
                    {reg.reviewedAt && <Row label="Reviewed" value={format(new Date(reg.reviewedAt), 'PPP p')} />}
                    {reg.rejectionReason && (
                        <div>
                            <p className="text-muted-foreground">Rejection reason</p>
                            <p className="mt-1 rounded-md bg-destructive/10 px-3 py-2 text-destructive">
                                {reg.rejectionReason}
                            </p>
                        </div>
                    )}
                </CardContent>
            </Card>

            {reg.status === 'Pending' && (
                <div className="space-y-3">
                    {!showRejectForm ? (
                        <div className="flex gap-2">
                            <Button onClick={handleApprove} disabled={approve.isPending} className="gap-2">
                                <Check className="h-4 w-4" />
                                {approve.isPending ? 'Approving…' : 'Approve'}
                            </Button>
                            <Button variant="destructive" onClick={() => setShowRejectForm(true)} className="gap-2">
                                <X className="h-4 w-4" /> Reject
                            </Button>
                        </div>
                    ) : (
                        <div className="space-y-3 rounded-lg border border-destructive/30 p-4">
                            <Label htmlFor="reason">Rejection reason <span className="text-destructive">*</span></Label>
                            <Textarea
                                id="reason"
                                placeholder="Explain why this registration is being rejected…"
                                rows={3}
                                value={rejectReason}
                                onChange={(e) => setRejectReason(e.target.value)}
                            />
                            <div className="flex gap-2">
                                <Button
                                    variant="destructive"
                                    onClick={handleReject}
                                    disabled={!rejectReason.trim() || reject.isPending}
                                >
                                    {reject.isPending ? 'Rejecting…' : 'Confirm Reject'}
                                </Button>
                                <Button variant="outline" onClick={() => setShowRejectForm(false)}>Cancel</Button>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

function Row({ label, value }: { label: string; value: string }) {
    return (
        <div className="flex justify-between gap-4">
            <span className="text-muted-foreground shrink-0">{label}</span>
            <span className="font-medium text-right">{value}</span>
        </div>
    );
}