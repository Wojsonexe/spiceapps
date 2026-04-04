'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { AppSidebar } from '@/components/layout/AppSidebar';
import { Topbar } from '@/components/layout/Topbar';
import { authApi } from '@/lib/api';
import { useAuthStore } from '@/store/auth';

export default function PanelLayout({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const setUser = useAuthStore((s) => s.setUser);

    useEffect(() => {
        if (!authApi.isAuthenticated()) {
            router.replace('/login');
            return;
        }
        // Fetch profile silently on mount
        authApi.getProfile()
            .then(setUser)
            .catch(() => {
                sessionStorage.removeItem('access_token');
                router.replace('/login');
            });
    }, [router, setUser]);

    return (
        <div className="flex h-screen bg-background">
            <AppSidebar />
            <div className="flex flex-1 flex-col overflow-hidden">
                <Topbar />
                <main className="flex-1 overflow-y-auto p-6">
                    {children}
                </main>
            </div>
        </div>
    );
}