"use client"

import { useRouter } from "next/navigation"
import { X } from "lucide-react"
import ConnectionsTab from "../connectionsTab"

export default function ConnectionsPage() {
    const router = useRouter()

    return (
        <div className="bg-white dark:bg-gray-900 text-black dark:text-white min-h-screen p-4 md:p-8">
            <div className="max-w-4xl mx-auto p-6 space-y-8">
                <div className="flex items-center justify-between">
                    <div>
                        <button
                            onClick={() => router.push("/settings")}
                            className="text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 mb-1"
                        >
                            ← Ustawienia
                        </button>
                        <h1 className="text-3xl font-bold">Połączone konta</h1>
                    </div>
                    <button
                        onClick={() => router.back()}
                        className="text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-100 transition-colors"
                        aria-label="Zamknij"
                    >
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <ConnectionsTab />
            </div>
        </div>
    )
}
