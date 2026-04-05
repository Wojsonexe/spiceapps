'use client';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState, Suspense } from 'react';
import { authApi } from '@/lib/api';
import { useAuthStore } from '@/store/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { toast } from 'sonner';
import type { AxiosError } from 'axios';

const SPICEAUTH_URL = process.env.NEXT_PUBLIC_SPICEAUTH_URL ?? 'http://localhost:5045';

const schema = z.object({
    email: z.string().email('Nieprawidłowy email'),
    password: z.string().min(1, 'Hasło jest wymagane'),
});
type FormData = z.infer<typeof schema>;

function LoginForm() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const setUser = useAuthStore((s) => s.setUser);
    const [loading, setLoading] = useState(false);

    const returnUrl = searchParams.get('returnUrl');
    const isOAuthFlow = !!returnUrl;

    const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
        resolver: zodResolver(schema),
    });

    const onSubmit = async (data: FormData) => {
        setLoading(true);
        try {
            if (isOAuthFlow) {
                // OAuth flow — przekaż credentials do SpiceAuth przez formularz HTML
                // Tworzymy i submitujemy ukryty formularz żeby zachować cookies
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = `${SPICEAUTH_URL}/api/oauth/account/login?returnUrl=${encodeURIComponent(returnUrl)}`;

                const addField = (name: string, value: string) => {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = name;
                    input.value = value;
                    form.appendChild(input);
                };

                addField('Email', data.email);
                addField('Password', data.password);
                addField('RememberMe', 'false');

                document.body.appendChild(form);
                form.submit();
                // nie ustawiamy setLoading(false) bo przeglądarka przechodzi do innej strony
                return;
            }

            // Normalny admin login
            await authApi.login(data);
            const profile = await authApi.getProfile();
            setUser(profile);
            router.replace('/dashboard');
        } catch (e) {
            const err = e as AxiosError<{ detail?: string; message?: string }>;
            toast.error(
                err.response?.data?.detail ||
                err.response?.data?.message ||
                'Nieprawidłowy email lub hasło'
            );
            setLoading(false);
        }
    };

    return (
        <div className="flex min-h-screen items-center justify-center bg-background p-4">
            <Card className="w-full max-w-sm">
                <CardHeader className="text-center">
                    <div className="text-3xl mb-2">🔐</div>
                    <CardTitle>{isOAuthFlow ? 'SpiceAuth' : 'SpiceAuth Admin'}</CardTitle>
                    <CardDescription>
                        {isOAuthFlow
                            ? 'Zaloguj się aby kontynuować'
                            : 'Sign in to your admin account'}
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                        <div className="space-y-1.5">
                            <Label htmlFor="email">Email</Label>
                            <Input
                                id="email"
                                type="email"
                                placeholder="admin@example.com"
                                autoComplete="email"
                                {...register('email')}
                            />
                            {errors.email && (
                                <p className="text-xs text-destructive">{errors.email.message}</p>
                            )}
                        </div>
                        <div className="space-y-1.5">
                            <Label htmlFor="password">
                                {isOAuthFlow ? 'Hasło' : 'Password'}
                            </Label>
                            <Input
                                id="password"
                                type="password"
                                autoComplete="current-password"
                                {...register('password')}
                            />
                            {errors.password && (
                                <p className="text-xs text-destructive">{errors.password.message}</p>
                            )}
                        </div>
                        <Button type="submit" className="w-full" disabled={loading}>
                            {loading
                                ? (isOAuthFlow ? 'Logowanie…' : 'Signing in…')
                                : (isOAuthFlow ? 'Zaloguj się' : 'Sign in')}
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}

export default function LoginPage() {
    return (
        <Suspense>
            <LoginForm />
        </Suspense>
    );
}