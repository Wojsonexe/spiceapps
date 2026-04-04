'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
    LayoutDashboard, Users, Shield, AppWindow,
    ClipboardList, Settings, LogOut, Plus,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { useAuthStore } from '@/store/auth';
import { authApi } from '@/lib/api';
import { usePendingRegistrations } from '@/hooks/use-registrations';

const navItems = [
    { href: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { href: '/registrations', icon: ClipboardList, label: 'Registrations', badge: true },
    { href: '/applications', icon: AppWindow, label: 'Applications' },
    { href: '/users', icon: Users, label: 'Users' },
    { href: '/audit-logs', icon: Shield, label: 'Audit Logs' },
];

export function AppSidebar() {
    const pathname = usePathname();
    const logout = useAuthStore((s) => s.logout);
    const { data: pending } = usePendingRegistrations();
    const pendingCount = pending?.length ?? 0;

    const handleLogout = () => {
        logout();
        authApi.logout();
    };

    return (
        <div className="flex h-screen w-[240px] flex-col border-r border-sidebar-border bg-sidebar shrink-0">
            {/* Header */}
            <div className="flex h-14 items-center border-b border-sidebar-border px-5">
                <h1 className="text-base font-semibold text-sidebar-foreground">🔐 SpiceAuth</h1>
            </div>

            {/* Nav */}
            <ScrollArea className="flex-1 px-3 py-3">
                <nav className="space-y-0.5">
                    {navItems.map(({ href, icon: Icon, label, badge }) => {
                        const active = pathname === href || pathname.startsWith(href + '/');
                        return (
                            <Link
                                key={href}
                                href={href}
                                className={cn(
                                    'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                                    active
                                        ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                                        : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
                                )}
                            >
                                <Icon className="h-4 w-4 shrink-0" />
                                <span className="flex-1">{label}</span>
                                {badge && pendingCount > 0 && (
                                    <Badge variant="destructive" className="h-5 px-1.5 text-xs">
                                        {pendingCount}
                                    </Badge>
                                )}
                            </Link>
                        );
                    })}

                    {/* Applications quick add */}
                    <div className="pt-4">
                        <div className="mb-1 flex items-center justify-between px-3">
              <span className="text-xs font-semibold uppercase text-muted-foreground">
                Applications
              </span>
                            <Button variant="ghost" size="icon" className="h-5 w-5" asChild>
                                <Link href="/applications/new">
                                    <Plus className="h-3 w-3" />
                                </Link>
                            </Button>
                        </div>
                    </div>
                </nav>
            </ScrollArea>

            {/* Footer */}
            <div className="border-t border-sidebar-border p-3 space-y-0.5">
                <Link
                    href="/settings"
                    className={cn(
                        'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                        pathname === '/settings'
                            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                            : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
                    )}
                >
                    <Settings className="h-4 w-4" />
                    Settings
                </Link>
                <button
                    onClick={handleLogout}
                    className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-sidebar-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
                >
                    <LogOut className="h-4 w-4" />
                    Logout
                </button>
            </div>
        </div>
    );
}