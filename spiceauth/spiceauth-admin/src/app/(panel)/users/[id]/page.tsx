'use client';

import { use } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Check, X, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useUser, useAllRoles, useUserRoles, useAssignRole, useRemoveRole } from '@/hooks/use-users';

export default function UserDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const router = useRouter();

    const { data: user, isLoading: userLoading } = useUser(id);
    const { data: allRoles = [], isLoading: rolesLoading } = useAllRoles();
    const { data: userRoles = [], isLoading: userRolesLoading } = useUserRoles(id);

    const assignRole = useAssignRole(id);
    const removeRole = useRemoveRole(id);

    const userRoleNames = new Set(userRoles.map((r: { name: string }) => r.name));
    const isLoading = userLoading || rolesLoading || userRolesLoading;

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">
                Loading…
            </div>
        );
    }

    if (!user) {
        return (
            <div className="text-center py-12 text-muted-foreground">User not found.</div>
        );
    }

    return (
        <div className="max-w-2xl space-y-6">
            <Button variant="ghost" size="sm" onClick={() => router.back()} className="-ml-2">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back
            </Button>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        {user.firstName && user.lastName
                            ? `${user.firstName} ${user.lastName}`
                            : user.username}
                        {user.isSuspended && (
                            <Badge variant="destructive">Suspended</Badge>
                        )}
                        {!user.isActive && (
                            <Badge variant="secondary">Inactive</Badge>
                        )}
                    </CardTitle>
                    <CardDescription>{user.email}</CardDescription>
                </CardHeader>
                <CardContent className="text-sm space-y-1 text-muted-foreground">
                    <p>Username: <span className="text-foreground font-mono">{user.username}</span></p>
                    <p>Email verified: <span className="text-foreground">{user.isEmailVerified ? 'Yes' : 'No'}</span></p>
                    <p>Created: <span className="text-foreground">{new Date(user.createdAt).toLocaleDateString()}</span></p>
                    {user.lastLoginAt && (
                        <p>Last login: <span className="text-foreground">{new Date(user.lastLoginAt).toLocaleDateString()}</span></p>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <ShieldCheck className="h-5 w-5" />
                        Roles
                    </CardTitle>
                    <CardDescription>
                        Toggle roles for this user. Changes take effect on next login.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {allRoles.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No roles defined in SpiceAuth yet.</p>
                    ) : (
                        <div className="divide-y divide-border">
                            {allRoles.map((role: { id: string; name: string; description: string | null; isSystemRole: boolean }) => {
                                const assigned = userRoleNames.has(role.name);
                                const isPending =
                                    (assignRole.isPending && assignRole.variables === role.name) ||
                                    (removeRole.isPending && removeRole.variables === role.name);

                                return (
                                    <div key={role.id} className="flex items-center justify-between py-3">
                                        <div>
                                            <p className="text-sm font-medium flex items-center gap-2">
                                                {role.name}
                                                {role.isSystemRole && (
                                                    <Badge variant="outline" className="text-[10px]">system</Badge>
                                                )}
                                            </p>
                                            {role.description && (
                                                <p className="text-xs text-muted-foreground">{role.description}</p>
                                            )}
                                        </div>
                                        <Button
                                            size="sm"
                                            variant={assigned ? 'default' : 'outline'}
                                            disabled={isPending}
                                            onClick={() =>
                                                assigned
                                                    ? removeRole.mutate(role.name)
                                                    : assignRole.mutate(role.name)
                                            }
                                            className="min-w-[90px]"
                                        >
                                            {assigned ? (
                                                <><Check className="mr-1 h-3 w-3" /> Assigned</>
                                            ) : (
                                                <><X className="mr-1 h-3 w-3" /> Not assigned</>
                                            )}
                                        </Button>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
