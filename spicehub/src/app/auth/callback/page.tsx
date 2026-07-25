"use client"

import { Suspense, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { setCookie } from "typescript-cookie"

function CallbackInner() {
    const router = useRouter()
    const params = useSearchParams()

    useEffect(() => {
        const accessToken = params.get("access_token")
        const refreshToken = params.get("refresh_token")

        if (!accessToken || !refreshToken) {
            router.replace("/login?error=discord_failed")
            return
        }

        const accessExpires = new Date()
        accessExpires.setDate(accessExpires.getDate() + 2)

        setCookie("refreshToken", refreshToken, { expires: 30 })
        setCookie("accessToken", accessToken, { expires: accessExpires })

        // replace() removes the token-bearing URL from browser history
        router.replace("/dashboard")
    }, [params, router])

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
            <p className="text-gray-500 dark:text-gray-400 text-sm">Trwa logowanie...</p>
        </div>
    )
}

export default function AuthCallbackPage() {
    return (
        <Suspense fallback={
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                <p className="text-gray-500 dark:text-gray-400 text-sm">Trwa logowanie...</p>
            </div>
        }>
            <CallbackInner />
        </Suspense>
    )
}
