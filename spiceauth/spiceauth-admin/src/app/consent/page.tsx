'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ShieldCheck, User, Mail, Info } from 'lucide-react';

const SPICEAUTH_URL = process.env.NEXT_PUBLIC_SPICEAUTH_URL ?? 'http://localhost:5045';

const SCOPE_LABELS: Record<string, { label: string; icon: React.ReactNode; description: string }> = {
    openid: {
        label: 'OpenID',
        icon: <ShieldCheck className="w-4 h-4" />,
        description: 'Weryfikacja tożsamości',
    },
    profile: {
        label: 'Profil',
        icon: <User className="w-4 h-4" />,
        description: 'Imię, nazwisko, nazwa użytkownika',
    },
    email: {
        label: 'Email',
        icon: <Mail className="w-4 h-4" />,
        description: 'Adres email',
    },
};

function ConsentForm() {
    const searchParams = useSearchParams();

    const clientId            = searchParams.get('clientId') ?? '';
    const clientName          = searchParams.get('clientName') ?? clientId;
    const clientDescription   = searchParams.get('clientDescription') ?? '';
    const redirectUri         = searchParams.get('redirectUri') ?? '';
    const scope               = searchParams.get('scope') ?? '';
    const state               = searchParams.get('state') ?? '';
    const codeChallenge       = searchParams.get('codeChallenge') ?? '';
    const codeChallengeMethod = searchParams.get('codeChallengeMethod') ?? '';
    const nonce               = searchParams.get('nonce') ?? '';

    const scopes = scope.split(' ').filter(Boolean);

    const submitConsent = (approved: boolean) => {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `${SPICEAUTH_URL}/api/oauth/authorize/consent`;

        const fields: Record<string, string> = {
            approved:           approved ? 'true' : 'false',
            clientId,
            redirectUri,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod,
            nonce,
        };

        Object.entries(fields).forEach(([name, value]) => {
            const input = document.createElement('input');
            input.type  = 'hidden';
            input.name  = name;
            input.value = value;
            form.appendChild(input);
        });

        document.body.appendChild(form);
        form.submit();
    };

    if (!clientId || !redirectUri) {
        return (
            <div className="flex min-h-screen items-center justify-center">
                <p className="text-destructive">Nieprawidłowe żądanie autoryzacji.</p>
            </div>
        );
    }

    return (
        <div className="flex min-h-screen items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center">
                    <div className="text-4xl mb-3">🔐</div>
                    <CardTitle className="text-xl">Zezwól na dostęp</CardTitle>
                    <CardDescription>
                        Aplikacja <strong>{clientName}</strong> prosi o dostęp do Twojego konta
                    </CardDescription>
                    {clientDescription && (
                        <div className="flex items-start gap-2 mt-2 p-3 bg-muted rounded-lg text-sm text-muted-foreground text-left">
                            <Info className="w-4 h-4 mt-0.5 shrink-0" />
                            <span>{clientDescription}</span>
                        </div>
                    )}
                </CardHeader>

                <CardContent className="space-y-4">
                    {/* Żądane uprawnienia */}
                    <div>
                        <p className="text-sm font-medium mb-2">Żądane uprawnienia:</p>
                        <div className="space-y-2">
                            {scopes.map((s) => {
                                const info = SCOPE_LABELS[s];
                                return (
                                    <div
                                        key={s}
                                        className="flex items-center gap-3 p-3 border rounded-lg"
                                    >
                                        <div className="text-primary">
                                            {info?.icon ?? <ShieldCheck className="w-4 h-4" />}
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex items-center gap-2">
                                                <span className="text-sm font-medium">
                                                    {info?.label ?? s}
                                                </span>
                                                <Badge variant="secondary" className="text-xs">
                                                    {s}
                                                </Badge>
                                            </div>
                                            {info?.description && (
                                                <p className="text-xs text-muted-foreground">
                                                    {info.description}
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Przyciski */}
                    <div className="flex gap-3 pt-2">
                        <Button
                            variant="outline"
                            className="flex-1"
                            onClick={() => submitConsent(false)}
                        >
                            Odmów
                        </Button>
                        <Button
                            className="flex-1"
                            onClick={() => submitConsent(true)}
                        >
                            Zezwól
                        </Button>
                    </div>

                    <p className="text-xs text-center text-muted-foreground">
                        Autoryzujesz aplikację <strong>{clientName}</strong> do dostępu
                        do Twojego konta SpiceAuth.
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}

export default function ConsentPage() {
    return (
        <Suspense>
            <ConsentForm />
        </Suspense>
    );
}