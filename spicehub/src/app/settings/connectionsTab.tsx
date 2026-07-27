"use client"

import { Suspense, useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import { toast } from "sonner"
import { spiceauthApi, LinkedProvider } from "@/services/spiceauth-api"
import { Button } from "@/components/ui/button"

const DiscordIcon = ({ className }: { className?: string }) => (
    <svg className={className} viewBox="0 0 127.14 96.36" fill="currentColor" aria-hidden>
        <path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z" />
    </svg>
)

function ConnectionsContent() {
    const params = useSearchParams()
    const [providers, setProviders] = useState<LinkedProvider[]>([])
    const [loading, setLoading] = useState(true)
    const [unlinking, setUnlinking] = useState(false)
    const spiceAuthUrl = process.env.NEXT_PUBLIC_SPICEAUTH_URL ?? ""

    useEffect(() => {
        const discordStatus = params.get("discord")
        if (discordStatus === "success") {
            toast.success("Discord połączony!", {
                description: "Konto Discord zostało pomyślnie połączone.",
            })
        } else if (discordStatus === "already_linked") {
            toast.error("Nie można połączyć Discord", {
                description: "To konto Discord jest już przypisane do innego użytkownika.",
            })
        }
    }, [params])

    useEffect(() => {
        let cancelled = false
        spiceauthApi
            .getLinkedProviders()
            .then((data) => { if (!cancelled) setProviders(data) })
            .catch(() => { if (!cancelled) toast.error("Nie udało się pobrać listy połączeń") })
            .finally(() => { if (!cancelled) setLoading(false) })
        return () => { cancelled = true }
    }, [])

    async function handleUnlink() {
        if (!confirm("Czy na pewno chcesz odłączyć konto Discord?")) return
        setUnlinking(true)
        try {
            await spiceauthApi.unlinkDiscord()
            toast.success("Discord odłączony", {
                description: "Konto Discord zostało odłączone od Twojego konta.",
            })
            setProviders((prev) => prev.filter((p) => p.provider !== "discord"))
        } catch (err: any) {
            let msg = err?.message ?? ""
            try {
                const parsed = JSON.parse(msg)
                msg = parsed.error ?? parsed.message ?? msg
            } catch {}

            const isLastMethod = msg.includes("jedyna") || msg.includes("brak hasła")
            toast.error("Nie można odłączyć Discord", {
                description: isLastMethod
                    ? "Discord to jedyna metoda logowania. Najpierw ustaw hasło do konta."
                    : "Wystąpił błąd. Spróbuj ponownie.",
            })
        } finally {
            setUnlinking(false)
        }
    }

    if (loading) {
        return (
            <div className="space-y-4">
                <div className="h-20 rounded-xl bg-gray-100 dark:bg-gray-800 animate-pulse" />
            </div>
        )
    }

    const discord = providers.find((p) => p.provider === "discord")

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                    Połączone konta
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Połącz zewnętrzne konta, żeby logować się bez hasła.
                </p>
            </div>

            <div className="flex items-center justify-between p-4 rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-[#5865F2] flex items-center justify-center flex-shrink-0">
                        <DiscordIcon className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <p className="font-medium text-gray-900 dark:text-gray-100">Discord</p>
                        {discord ? (
                            <div className="flex items-center gap-2 mt-0.5">
                                {discord.avatar_url && (
                                    <img
                                        src={discord.avatar_url}
                                        alt=""
                                        className="w-4 h-4 rounded-full"
                                    />
                                )}
                                <p className="text-sm text-gray-500 dark:text-gray-400">
                                    {discord.provider_username ?? discord.provider_user_id}
                                </p>
                            </div>
                        ) : (
                            <p className="text-sm text-gray-500 dark:text-gray-400">Nie połączono</p>
                        )}
                    </div>
                </div>

                {discord ? (
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={handleUnlink}
                        disabled={unlinking}
                        className="text-red-600 dark:text-red-400 border-red-200 dark:border-red-800
                                   hover:bg-red-50 dark:hover:bg-red-900/20"
                    >
                        {unlinking ? "Odłączanie..." : "Odłącz"}
                    </Button>
                ) : (
                    <a
                        href={`${spiceAuthUrl}/api/oauth/external/discord/login`}
                        className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium
                                   rounded-md text-white bg-[#5865F2] hover:bg-[#4752C4] transition-colors"
                    >
                        <DiscordIcon className="w-4 h-4" />
                        Połącz
                    </a>
                )}
            </div>
        </div>
    )
}

export default function ConnectionsTab() {
    return (
        <Suspense
            fallback={
                <div className="h-20 rounded-xl bg-gray-100 dark:bg-gray-800 animate-pulse" />
            }
        >
            <ConnectionsContent />
        </Suspense>
    )
}
