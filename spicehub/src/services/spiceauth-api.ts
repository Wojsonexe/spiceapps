import { getCookie, setCookie } from "typescript-cookie"
import { getBackendUrl } from "@/app/serveractions/backend-url"

let refreshPromise: Promise<string> | null = null

function jwtExpiresWithinSeconds(token: string, seconds: number): boolean {
    try {
        const parts = token.split(".")
        if (parts.length !== 3) return true
        const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
        const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4)
        const decoded = JSON.parse(atob(padded))
        if (typeof decoded.exp !== "number") return true
        const nowSec = Math.floor(Date.now() / 1000)
        return decoded.exp - nowSec < seconds
    } catch {
        return true
    }
}

async function doRefresh(): Promise<string> {
    const rt = getCookie("refreshToken")
    if (!rt) throw new Error("Not authenticated")

    const backendUrl = await getBackendUrl()
    if (!backendUrl) throw new Error("Backend not configured")

    const res = await fetch(`${backendUrl}/api/auth/generateAccess`, {
        method: "POST",
        cache: "no-store",
        headers: { Authorization: rt },
    })
    if (!res.ok) throw new Error("Token refresh failed")

    const fresh = await res.text()
    const exp = new Date()
    exp.setDate(exp.getDate() + 2)
    setCookie("accessToken", fresh, { expires: exp })
    return fresh
}

async function getAccessToken(): Promise<string> {
    const token = getCookie("accessToken")
    if (token && !jwtExpiresWithinSeconds(token, 60)) return token

    if (refreshPromise) return refreshPromise

    refreshPromise = doRefresh().finally(() => {
        refreshPromise = null
    })

    return refreshPromise
}

async function spiceauthFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const base = process.env.NEXT_PUBLIC_SPICEAUTH_URL
    if (!base) throw new Error("NEXT_PUBLIC_SPICEAUTH_URL not configured")

    const token = await getAccessToken()

    const res = await fetch(`${base}${path}`, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
            ...options.headers,
        },
    })

    if (!res.ok) throw new Error(await res.text())
    return res.json() as Promise<T>
}

export type LinkedProvider = {
    provider: string
    provider_user_id: string
    provider_username: string | null
    provider_email: string | null
    linked_at: string
    avatar_url: string | null
}

export const spiceauthApi = {
    getLinkedProviders: () =>
        spiceauthFetch<LinkedProvider[]>("/api/oauth/external/providers"),

    unlinkDiscord: () =>
        spiceauthFetch<{ message: string }>("/api/oauth/external/discord/unlink", {
            method: "DELETE",
        }),
}
