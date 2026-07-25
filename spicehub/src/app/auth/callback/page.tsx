"use client"
import { useEffect, useRef, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { setCookie } from "typescript-cookie";
import Loading from "@/components/Loading";

function AuthCallbackInner() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const calledRef = useRef(false);

    useEffect(() => {
        if (calledRef.current) return;
        calledRef.current = true;
        const accessToken  = searchParams.get("access_token");
        const refreshToken = searchParams.get("refresh_token");
        const error        = searchParams.get("error");
        if (error || !accessToken || !refreshToken) {
            router.replace("/login?error=" + (error ?? "missing_token"));
            return;
        }
        const accessExpiry = new Date();
        accessExpiry.setDate(accessExpiry.getDate() + 2);
        setCookie("accessToken",  accessToken,  { expires: accessExpiry });
        setCookie("refreshToken", refreshToken, { expires: 30 });
        router.replace("/dashboard");
    }, [searchParams, router]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
            <Loading />
        </div>
    );
}

export default function AuthCallbackPage() {
    return (
        <Suspense fallback={<div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900"><Loading /></div>}>
            <AuthCallbackInner />
        </Suspense>
    );
}
