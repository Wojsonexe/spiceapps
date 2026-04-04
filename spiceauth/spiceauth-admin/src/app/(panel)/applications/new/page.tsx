'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRegisterClient } from '@/hooks/use-applications';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
    Dialog, DialogContent, DialogDescription,
    DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { CopyButton } from '@/components/ui/copy-button';
import { ArrowLeft, Plus, X } from 'lucide-react';
import type { ClientRegistrationResponse } from '@/types';

const COMMON_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

const schema = z.object({
    name: z.string().min(1, 'Name is required'),
    description: z.string().optional(),
    clientType: z.enum(['Confidential', 'Public']),
    requireConsent: z.boolean(),
    requirePkce: z.boolean(),
});
type FormData = z.infer<typeof schema>;

export default function NewApplicationPage() {
    const router = useRouter();
    const registerClient = useRegisterClient();

    const [redirectUris, setRedirectUris] = useState<string[]>(['']);
    const [allowedScopes, setAllowedScopes] = useState<string[]>(['openid', 'profile']);
    const [createdClient, setCreatedClient] = useState<ClientRegistrationResponse | null>(null);

    const { register, handleSubmit, watch, setValue, formState: { errors } } = useForm<FormData>({
        resolver: zodResolver(schema),
        defaultValues: {
            clientType: 'Confidential',
            requireConsent: true,
            requirePkce: true,
        },
    });

    const clientType = watch('clientType');

    const addRedirectUri = () => setRedirectUris(p => [...p, '']);
    const updateRedirectUri = (i: number, v: string) =>
        setRedirectUris(p => p.map((u, idx) => idx === i ? v : u));
    const removeRedirectUri = (i: number) =>
        setRedirectUris(p => p.filter((_, idx) => idx !== i));

    const toggleScope = (scope: string) =>
        setAllowedScopes(p => p.includes(scope) ? p.filter(s => s !== scope) : [...p, scope]);

    const onSubmit = (data: FormData) => {
        const uris = redirectUris.filter(Boolean);
        if (!uris.length) return;
        registerClient.mutate(
            { ...data, redirectUris: uris, allowedScopes },
            { onSuccess: (res) => setCreatedClient(res) }
        );
    };

    return (
        <div className="max-w-2xl space-y-6">
            <Button variant="ghost" size="sm" onClick={() => router.back()} className="-ml-2">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
            </Button>

            <div>
                <h2 className="text-2xl font-bold tracking-tight">New Application</h2>
                <p className="text-muted-foreground">Register a new OAuth 2.1 client</p>
            </div>

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                <Card>
                    <CardHeader><CardTitle>Basic Info</CardTitle></CardHeader>
                    <CardContent className="space-y-4">
                        <div className="space-y-1.5">
                            <Label htmlFor="name">Name <span className="text-destructive">*</span></Label>
                            <Input id="name" placeholder="My Application" {...register('name')} />
                            {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="description">Description</Label>
                            <Input id="description" placeholder="Optional description" {...register('description')} />
                        </div>
                        <div className="space-y-1.5">
                            <Label>Client Type</Label>
                            <div className="flex gap-2">
                                {(['Confidential', 'Public'] as const).map((t) => (
                                    <button
                                        key={t}
                                        type="button"
                                        onClick={() => setValue('clientType', t)}
                                        className={`flex-1 rounded-md border px-4 py-2 text-sm font-medium transition-colors ${
                                            clientType === t
                                                ? 'border-primary bg-primary/10 text-primary'
                                                : 'border-border hover:bg-muted'
                                        }`}
                                    >
                                        {t}
                                    </button>
                                ))}
                            </div>
                            <p className="text-xs text-muted-foreground">
                                {clientType === 'Confidential'
                                    ? 'Server-side apps that can keep a secret. Receives a client_secret.'
                                    : 'SPAs/mobile apps. PKCE required, no client_secret.'}
                            </p>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Redirect URIs</CardTitle>
                        <CardDescription>Allowed callback URLs after authorization</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-2">
                        {redirectUris.map((uri, i) => (
                            <div key={i} className="flex gap-2">
                                <Input
                                    value={uri}
                                    onChange={(e) => updateRedirectUri(i, e.target.value)}
                                    placeholder="https://myapp.com/callback"
                                    className="font-mono text-sm"
                                />
                                {redirectUris.length > 1 && (
                                    <Button type="button" variant="ghost" size="icon" onClick={() => removeRedirectUri(i)}>
                                        <X className="h-4 w-4" />
                                    </Button>
                                )}
                            </div>
                        ))}
                        <Button type="button" variant="outline" size="sm" onClick={addRedirectUri}>
                            <Plus className="mr-2 h-4 w-4" /> Add URI
                        </Button>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Scopes</CardTitle>
                        <CardDescription>Access scopes this client can request</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="flex flex-wrap gap-2">
                            {COMMON_SCOPES.map(scope => (
                                <button
                                    key={scope}
                                    type="button"
                                    onClick={() => toggleScope(scope)}
                                    className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                                        allowedScopes.includes(scope)
                                            ? 'border-primary bg-primary text-primary-foreground'
                                            : 'border-border hover:bg-muted'
                                    }`}
                                >
                                    {scope}
                                </button>
                            ))}
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader><CardTitle>Options</CardTitle></CardHeader>
                    <CardContent className="space-y-3">
                        <label className="flex items-center justify-between">
                            <div>
                                <p className="text-sm font-medium">Require Consent</p>
                                <p className="text-xs text-muted-foreground">Show consent screen to users</p>
                            </div>
                            <input type="checkbox" {...register('requireConsent')} className="h-4 w-4" />
                        </label>
                        <label className="flex items-center justify-between">
                            <div>
                                <p className="text-sm font-medium">Require PKCE</p>
                                <p className="text-xs text-muted-foreground">Enforce PKCE for token exchange</p>
                            </div>
                            <input type="checkbox" {...register('requirePkce')} className="h-4 w-4" />
                        </label>
                    </CardContent>
                </Card>

                <div className="flex gap-2">
                    <Button type="submit" disabled={registerClient.isPending}>
                        {registerClient.isPending ? 'Registering…' : 'Register Application'}
                    </Button>
                    <Button type="button" variant="outline" onClick={() => router.back()}>Cancel</Button>
                </div>
            </form>

            {/* Secret reveal dialog — shown once after creation */}
            <Dialog open={!!createdClient} onOpenChange={() => {}}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>✅ Application Registered</DialogTitle>
                        <DialogDescription>
                            Save your credentials now. The client secret will <strong>never be shown again</strong>.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                        <div className="space-y-1.5">
                            <Label>Client ID</Label>
                            <div className="flex gap-2">
                                <Input value={createdClient?.clientId ?? ''} readOnly className="font-mono text-sm" />
                                <CopyButton value={createdClient?.clientId ?? ''} />
                            </div>
                        </div>
                        {createdClient?.clientSecret && (
                            <div className="space-y-1.5">
                                <Label>Client Secret</Label>
                                <div className="flex gap-2">
                                    <Input value={createdClient.clientSecret} readOnly className="font-mono text-sm" />
                                    <CopyButton value={createdClient.clientSecret} />
                                </div>
                            </div>
                        )}
                    </div>
                    <Button
                        className="w-full"
                        onClick={() => {
                            setCreatedClient(null);
                            router.push('/applications');
                        }}
                    >
                        I&#39;ve saved my credentials
                    </Button>
                </DialogContent>
            </Dialog>
        </div>
    );
}