'use client';

import { useQuery } from '@tanstack/react-query';
import { clientsApi, registrationApi, wellKnownApi } from '@/lib/api';
import { useRegistrationStats } from '@/hooks/use-registrations';
import { AppWindow, Users, ClipboardCheck, Wifi } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';

function StatCard({
                      title, value, icon: Icon, loading, description,
                  }: {
    title: string; value?: number | string; icon: React.ElementType;
    loading?: boolean; description?: string;
}) {
    return (
        <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
                <Icon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
                {loading ? (
                    <Skeleton className="h-8 w-16" />
                ) : (
                    <>
                        <p className="text-2xl font-bold">{value ?? '—'}</p>
                        {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
                    </>
                )}
            </CardContent>
        </Card>
    );
}

export default function DashboardPage() {
    const { data: clients, isLoading: loadingClients } = useQuery({
        queryKey: ['clients'],
        queryFn: clientsApi.getAll,
    });
    const { data: stats, isLoading: loadingStats } = useRegistrationStats();
    const { data: pending, isLoading: loadingPending } = useQuery({
        queryKey: ['registrations', 'pending'],
        queryFn: registrationApi.getPending,
    });
    const { data: oidcConfig, isError: oidcError } = useQuery({
        queryKey: ['well-known'],
        queryFn: wellKnownApi.getOpenIdConfig,
        retry: false,
    });

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
                <p className="text-muted-foreground">Overview of your authorization server</p>
            </div>

            {/* Stat cards */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <StatCard
                    title="Applications"
                    value={clients?.length}
                    icon={AppWindow}
                    loading={loadingClients}
                />
                <StatCard
                    title="Total Registrations"
                    value={stats?.totalRequests}
                    icon={Users}
                    loading={loadingStats}
                />
                <StatCard
                    title="Pending Approvals"
                    value={stats?.pendingRequests}
                    icon={ClipboardCheck}
                    loading={loadingStats}
                    description={stats?.pendingRequests ? 'Needs review' : 'All clear'}
                />
                <StatCard
                    title="Server Status"
                    value={oidcError ? 'Offline' : 'Online'}
                    icon={Wifi}
                    description={oidcConfig?.issuer}
                />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {/* Pending registrations queue */}
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-3">
                        <CardTitle className="text-base">Pending Registrations</CardTitle>
                        <Button variant="ghost" size="sm" asChild>
                            <Link href="/registrations">View all</Link>
                        </Button>
                    </CardHeader>
                    <CardContent>
                        {loadingPending ? (
                            <div className="space-y-2">
                                {[1, 2, 3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
                            </div>
                        ) : pending?.length === 0 ? (
                            <p className="text-sm text-muted-foreground text-center py-6">
                                ✓ No pending registrations
                            </p>
                        ) : (
                            <div className="space-y-2">
                                {pending?.slice(0, 5).map((reg, index) => (
                                    <Link
                                        key={reg.id ?? `pending-${index}`}
                                        href={`/registrations/${reg.id}`}
                                        className="flex items-center justify-between rounded-md p-2 hover:bg-muted transition-colors"
                                    >
                                        <div>
                                            <p className="text-sm font-medium">{reg.username}</p>
                                            <p className="text-xs text-muted-foreground">{reg.email}</p>
                                        </div>
                                        <span className="text-xs text-muted-foreground">
                                            {formatDistanceToNow(new Date(reg.createdAt), { addSuffix: true })}
                                        </span>
                                    </Link>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Recent applications */}
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between pb-3">
                        <CardTitle className="text-base">Applications</CardTitle>
                        <Button variant="ghost" size="sm" asChild>
                            <Link href="/applications">View all</Link>
                        </Button>
                    </CardHeader>
                    <CardContent>
                        {loadingClients ? (
                            <div className="space-y-2">
                                {[1, 2, 3].map(i => <Skeleton key={i} className="h-10 w-full" />)}
                            </div>
                        ) : clients?.length === 0 ? (
                            <p className="text-sm text-muted-foreground text-center py-6">
                                No applications registered yet
                            </p>
                        ) : (
                            <div className="space-y-2">
                                {clients?.slice(0, 5).map((client, index) => (
                                    <Link
                                        key={client.clientId || `client-${index}`}
                                        href={`/applications/${client.clientId}`}
                                        className="flex items-center justify-between rounded-md p-2 hover:bg-muted transition-colors"
                                    >
                                        <p className="text-sm font-medium">{client.name}</p>
                                        <Badge variant={client.isActive ? 'default' : 'secondary'} className="text-xs">
                                            {client.clientType}
                                        </Badge>
                                    </Link>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}