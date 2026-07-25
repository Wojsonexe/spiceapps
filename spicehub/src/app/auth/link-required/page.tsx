"use client"

import { Suspense, useEffect, useRef, useState } from "react"
import { useSearchParams } from "next/navigation"
import { setCookie } from "typescript-cookie"
import { getBackendUrl } from "@/app/serveractions/backend-url"
import Link from "next/link"

const DiscordIcon = () => (
    <svg width="20" height="20" viewBox="0 0 127.14 96.36" fill="currentColor">
        <path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z" />
    </svg>
)

function LinkRequiredInner() {
    const params = useSearchParams()
    const hint = params.get("hint") ?? ""

    const passwordRef = useRef<HTMLInputElement>(null)
    const [error, setError] = useState<string | null>(null)
    const [loading, setLoading] = useState(false)
    const [loggedIn, setLoggedIn] = useState(false)
    const spiceAuthUrl = process.env.NEXT_PUBLIC_SPICEAUTH_URL ?? ""

    async function handleLogin() {
        setLoading(true)
        setError(null)

        const backendUrl = await getBackendUrl()
        if (!backendUrl) {
            setError("Błąd konfiguracji serwera")
            setLoading(false)
            return
        }

        try {
            const res = await fetch(`${backendUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ login: hint, password: passwordRef.current?.value }),
            })

            if (!res.ok) {
                setError("Nieprawidłowe hasło")
                return
            }

            const data = await res.json()
            if (data.refresh_Token && data.access_Token) {
                const accessExpires = new Date()
                accessExpires.setDate(accessExpires.getDate() + 2)
                setCookie("refreshToken", data.refresh_Token, { expires: 30 })
                setCookie("accessToken", data.access_Token, { expires: accessExpires })
                setLoggedIn(true)
            } else {
                setError("Nieprawidłowe hasło")
            }
        } catch {
            setError("Błąd połączenia z serwerem")
        } finally {
            setLoading(false)
        }
    }

    if (loggedIn) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4">
                <div className="max-w-md w-full text-center space-y-6">
                    <div className="text-5xl">✅</div>
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                        Zalogowano pomyślnie
                    </h2>
                    <p className="text-gray-600 dark:text-gray-400 text-sm">
                        Teraz możesz połączyć konto Discord z Twoim kontem SpiceHub.
                    </p>
                    <a
                        href={`${spiceAuthUrl}/api/oauth/external/discord/login`}
                        className="inline-flex items-center justify-center gap-3 w-full py-2.5 px-4
                                   rounded-md text-white font-medium text-sm
                                   bg-[#5865F2] hover:bg-[#4752C4] transition-colors"
                    >
                        <DiscordIcon />
                        Połącz Discord
                    </a>
                    <Link
                        href="/dashboard"
                        className="block text-sm text-gray-500 dark:text-gray-400 hover:underline"
                    >
                        Pomiń na razie →
                    </Link>
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4">
            <div className="max-w-md w-full space-y-6">
                <div className="bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-700
                               rounded-lg p-4 text-sm">
                    <p className="font-medium text-amber-800 dark:text-amber-200">
                        Konto z tym adresem email już istnieje
                    </p>
                    <p className="mt-1 text-amber-700 dark:text-amber-300">
                        Zaloguj się hasłem, żeby połączyć konto Discord z istniejącym kontem
                        {hint ? ` (${hint})` : ""}.
                    </p>
                </div>

                <div className="space-y-3">
                    <input
                        type="text"
                        value={hint}
                        readOnly
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600
                                   rounded-md sm:text-sm bg-gray-100 dark:bg-gray-700
                                   text-gray-500 dark:text-gray-400 cursor-not-allowed"
                    />
                    <input
                        type="password"
                        ref={passwordRef}
                        placeholder="Hasło"
                        onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 dark:border-gray-600
                                   rounded-md sm:text-sm bg-white dark:bg-gray-800
                                   text-gray-900 dark:text-gray-100 placeholder-gray-400
                                   focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    />

                    <button
                        onClick={handleLogin}
                        disabled={loading}
                        className="w-full flex justify-center py-2 px-4 border border-transparent
                                   text-sm font-medium rounded-md text-white
                                   bg-blue-600 hover:bg-blue-700 dark:bg-blue-500 dark:hover:bg-blue-600
                                   focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500
                                   disabled:opacity-60 transition-colors"
                    >
                        {loading ? "Logowanie..." : "Zaloguj się"}
                    </button>

                    {error && (
                        <p className="text-red-600 dark:text-red-400 text-sm text-center">{error}</p>
                    )}
                </div>

                <div className="text-center">
                    <Link
                        href="/login"
                        className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                    >
                        ← Wróć do logowania
                    </Link>
                </div>
            </div>
        </div>
    )
}

export default function LinkRequiredPage() {
    return (
        <Suspense fallback={
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                <p className="text-gray-500 dark:text-gray-400 text-sm">Ładowanie...</p>
            </div>
        }>
            <LinkRequiredInner />
        </Suspense>
    )
}
