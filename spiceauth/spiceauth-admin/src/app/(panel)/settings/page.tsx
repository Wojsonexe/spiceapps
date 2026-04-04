'use client';

import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery } from '@tanstack/react-query';
import { authApi } from '@/lib/api';
import { useAuthStore } from '@/store/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import type { AxiosError } from 'axios';

// ─── Profile form ─────────────────────────────────────────────────────────────

const profileSchema = z.object({
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    username: z.string().min(3, 'Min 3 characters').optional(),
});
type ProfileForm = z.infer<typeof profileSchema>;

// ─── Password form ────────────────────────────────────────────────────────────

const passwordSchema = z.object({
    currentPassword: z.string().min(1, 'Required'),
    newPassword: z.string().min(8, 'Min 8 characters'),
    confirmPassword: z.string().min(1, 'Required'),
}).refine(d => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
});
type PasswordForm = z.infer<typeof passwordSchema>;

// ─── Component ────────────────────────────────────────────────────────────────

export default function SettingsPage() {
    const setUser = useAuthStore(s => s.setUser);

    const { data: profile, isLoading } = useQuery({
        queryKey: ['profile'],
        queryFn: authApi.getProfile,
    });

    const profileForm = useForm<ProfileForm>({ resolver: zodResolver(profileSchema) });
    const passwordForm = useForm<PasswordForm>({ resolver: zodResolver(passwordSchema) });

    // Populate form when profile loads
    useEffect(() => {
        if (profile) {
            profileForm.reset({
                firstName: profile.firstName ?? '',
                lastName: profile.lastName ?? '',
                username: profile.username ?? '',
            });
        }
    }, [profile, profileForm]);

    const updateProfile = useMutation({
        mutationFn: authApi.updateProfile,
        onSuccess: (updated) => {
            setUser(updated);
            toast.success('Profile updated');
        },
        onError: (e: AxiosError<{ detail?: string }>) => {
            toast.error(e.response?.data?.detail || 'Failed to update profile');
        },
    });

    const changePassword = useMutation({
        mutationFn: authApi.changePassword,
        onSuccess: () => {
            toast.success('Password changed');
            passwordForm.reset();
        },
        onError: (e: AxiosError<{ detail?: string }>) => {
            toast.error(e.response?.data?.detail || 'Failed to change password');
        },
    });

    return (
        <div className="max-w-xl space-y-8">
            <div>
                <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
                <p className="text-muted-foreground">Manage your account preferences</p>
            </div>

            {/* Profile */}
            <Card>
                <CardHeader>
                    <CardTitle>Profile</CardTitle>
                    <CardDescription>Update your personal information</CardDescription>
                </CardHeader>
                <CardContent>
                    {isLoading ? (
                        <div className="space-y-3">
                            <Skeleton className="h-9 w-full" />
                            <Skeleton className="h-9 w-full" />
                            <Skeleton className="h-9 w-full" />
                        </div>
                    ) : (
                        <form
                            onSubmit={profileForm.handleSubmit(d => updateProfile.mutate(d))}
                            className="space-y-4"
                        >
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <Label>First name</Label>
                                    <Input {...profileForm.register('firstName')} />
                                </div>
                                <div className="space-y-1.5">
                                    <Label>Last name</Label>
                                    <Input {...profileForm.register('lastName')} />
                                </div>
                            </div>
                            <div className="space-y-1.5">
                                <Label>Username</Label>
                                <Input {...profileForm.register('username')} />
                                {profileForm.formState.errors.username && (
                                    <p className="text-xs text-destructive">
                                        {profileForm.formState.errors.username.message}
                                    </p>
                                )}
                            </div>
                            <div className="space-y-1.5">
                                <Label>Email</Label>
                                <Input value={profile?.email ?? ''} disabled className="bg-muted" />
                                <p className="text-xs text-muted-foreground">Email cannot be changed</p>
                            </div>
                            <Button type="submit" disabled={updateProfile.isPending}>
                                {updateProfile.isPending ? 'Saving…' : 'Save changes'}
                            </Button>
                        </form>
                    )}
                </CardContent>
            </Card>

            <Separator />

            {/* Password */}
            <Card>
                <CardHeader>
                    <CardTitle>Change Password</CardTitle>
                    <CardDescription>Use a strong password of at least 8 characters</CardDescription>
                </CardHeader>
                <CardContent>
                    <form
                        onSubmit={passwordForm.handleSubmit(d => changePassword.mutate(d))}
                        className="space-y-4"
                    >
                        <div className="space-y-1.5">
                            <Label>Current password</Label>
                            <Input type="password" autoComplete="current-password" {...passwordForm.register('currentPassword')} />
                            {passwordForm.formState.errors.currentPassword && (
                                <p className="text-xs text-destructive">{passwordForm.formState.errors.currentPassword.message}</p>
                            )}
                        </div>
                        <div className="space-y-1.5">
                            <Label>New password</Label>
                            <Input type="password" autoComplete="new-password" {...passwordForm.register('newPassword')} />
                            {passwordForm.formState.errors.newPassword && (
                                <p className="text-xs text-destructive">{passwordForm.formState.errors.newPassword.message}</p>
                            )}
                        </div>
                        <div className="space-y-1.5">
                            <Label>Confirm new password</Label>
                            <Input type="password" autoComplete="new-password" {...passwordForm.register('confirmPassword')} />
                            {passwordForm.formState.errors.confirmPassword && (
                                <p className="text-xs text-destructive">{passwordForm.formState.errors.confirmPassword.message}</p>
                            )}
                        </div>
                        <Button type="submit" disabled={changePassword.isPending}>
                            {changePassword.isPending ? 'Changing…' : 'Change password'}
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}