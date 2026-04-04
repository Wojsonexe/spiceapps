'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { ShieldCheck, ShieldX, User, Mail, IdCard, RefreshCw } from 'lucide-react';

// ─── Scope metadata ───────────────────────────────────────────────────────────

const SCOPE_META: Record<string, { label: string; description: string; icon: React.ElementType }> = {
    openid:         { label: 'Identity',       description: 'Access your basic account info',       icon: IdCard },
    profile:        { label: 'Profile',        description: 'Access your name and profile picture', icon: User },
    email:          { label: 'Email',          description: 'Access your email address',             icon: Mail },
    offline_access: { label: 'Stay logged in', description: 'Keep access without re-authorization', icon: RefreshCw },
};

// ─── Native form submit (handles cookies + 302 redirect properly) ─────────────

function submitConsent(fields: Record<string, string>, approved: boolean) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = `${process.env.NEXT_PUBLIC_SPICEAUTH_URL ?? 'http://localhost:5045'}/api/oauth/authorize/consent`;

    for (const [name, value] of Object.entries({ ...fields, approved: String(approved) })) {
        const input   = document.createElement('input');
        input.type    = 'hidden';
        input.name    = name;
        input.value   = value;
        form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
}

// ─── Consent form ─────────────────────────────────────────────────────────────

function ConsentForm() {
    const params = useSearchParams();
    const [loading, setLoading] = useState<'approve' | 'deny' | null>(null);

    const clientId            = params.get('clientId')            ?? '';
    const clientName          = params.get('clientName')          ?? 'Unknown App';
    const clientDescription   = params.get('clientDescription')   ?? '';
    const redirectUri         = params.get('redirectUri')         ?? '';
    const scope               = params.get('scope')               ?? '';
    const state               = params.get('state')               ?? '';
    const codeChallenge       = params.get('codeChallenge')       ?? '';
    const codeChallengeMethod = params.get('codeChallengeMethod') ?? '';
    const nonce               = params.get('nonce')               ?? '';

    const scopes     = scope.split(' ').filter(Boolean);
    const formFields = { clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce };

    if (!clientId || !redirectUri) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-[#667eea] to-[#764ba2] p-4">
                <Card className="w-full max-w-md shadow-2xl">
                    <CardContent className="pt-6 text-center text-sm text-muted-foreground">
                        Invalid consent request. Missing required parameters.
                    </CardContent>
                </Card>
            </div>
        );
    }

    const handleDeny = () => {
        setLoading('deny');
        submitConsent(formFields, false);
    };

    const handleApprove = () => {
        setLoading('approve');
        submitConsent(formFields, true);
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-[#667eea] to-[#764ba2] p-4">
            <Card className="w-full max-w-md shadow-2xl">
                <CardHeader className="text-center pb-2">
                    {/* App + user avatars */}
                    <div className="flex items-center justify-center gap-4 mb-4">
                        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-3xl border-2 border-background shadow-md">
                            🔐
                        </div>
                        <div className="flex items-center gap-1 text-muted-foreground/50">
                            <div className="h-px w-5 bg-border" />
                            <div className="h-1.5 w-1.5 rounded-full bg-border" />
                            <div className="h-px w-5 bg-border" />
                        </div>
                        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted border-2 border-background shadow-md text-2xl">
                            👤
                        </div>
                    </div>

                    <h1 className="text-xl font-bold">{clientName}</h1>
                    <p className="text-sm text-muted-foreground mt-1">
                        {clientDescription || 'wants to access your SpiceAuth account'}
                    </p>
                </CardHeader>

                <CardContent className="space-y-4">
                    {/* Scopes */}
                    <div>
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
                            Requested permissions
                        </p>
                        <ul className="space-y-2">
                            {scopes.map(s => {
                                const meta = SCOPE_META[s];
                                const Icon = meta?.icon ?? ShieldCheck;
                                return (
                                    <li key={s} className="flex items-center gap-3 rounded-lg bg-muted/50 px-3 py-2.5">
                                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/10">
                                            <Icon className="h-4 w-4 text-primary" />
                                        </div>
                                        <div>
                                            <p className="text-sm font-medium">{meta?.label ?? s}</p>
                                            <p className="text-xs text-muted-foreground">
                                                {meta?.description ?? `Access to ${s}`}
                                            </p>
                                        </div>
                                    </li>
                                );
                            })}
                        </ul>
                    </div>

                    {/* Redirect info */}
                    <div className="rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground">
                        <span className="font-medium">Redirects to: </span>
                        <span className="font-mono break-all">{redirectUri}</span>
                    </div>

                    {/* Trust note */}
                    <p className="text-center text-xs text-muted-foreground">
                        Make sure you trust{' '}
                        <span className="font-medium text-foreground">{clientName}</span>
                        {' '}before authorizing.
                    </p>

                    {/* Actions */}
                    <div className="flex gap-3 pt-1">
                        <Button
                            variant="outline"
                            className="flex-1"
                            onClick={handleDeny}
                            disabled={!!loading}
                        >
                            {loading === 'deny'
                                ? <span className="animate-pulse">Denying…</span>
                                : <><ShieldX className="h-4 w-4 mr-2" />Deny</>}
                        </Button>
                        <Button
                            className="flex-1"
                            onClick={handleApprove}
                            disabled={!!loading}
                        >
                            {loading === 'approve'
                                ? <span className="animate-pulse">Authorizing…</span>
                                : <><ShieldCheck className="h-4 w-4 mr-2" />Authorize</>}
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ConsentPage() {
    return (
        <Suspense fallback={
            <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-[#667eea] to-[#764ba2]">
                <p className="text-white/80 text-sm animate-pulse">Loading…</p>
            </div>
        }>
            <ConsentForm />
        </Suspense>
    );
}
