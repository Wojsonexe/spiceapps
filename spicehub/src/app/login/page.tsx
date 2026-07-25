"use client"

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import Loading from "@/components/Loading";
import { getBackendUrl } from "../serveractions/backend-url";

import { getCookie, setCookie} from 'typescript-cookie';
import Link from "next/link";
export default function LoginPage() {
    const email = useRef<HTMLInputElement>(null);
    const password = useRef<HTMLInputElement>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();

    useEffect(() => {
      let rt = getCookie("refreshToken");
      if (rt) router.push("/dashboard")
    
      return () => {
      }
    }, [])
    

    async function login() {
        setLoading(true);
        setError(null);
        const payload = {
            login: email.current?.value,
            password: password.current?.value,
        };

        let backendurl = await getBackendUrl();
        if (!backendurl) alert("env var error");
    
        try {
            const res = await fetch(backendurl+'/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });
    
            // Check for non-success responses
            if (!res.ok) {
                const errorData = await res.text();
                console.log(errorData);
                setError(errorData || 'Invalid login credentials');
                return; // exit early if login failed
            }
    
            const data = await res.json();
    
            if (data.refresh_Token && data.access_Token) {
                //localStorage.setItem('refreshToken', data.refresh_Token);
                //localStorage.setItem('accessToken', data.access_Token);
                let ad = new Date();
                ad.setDate(ad.getDate() + 2);
                setCookie("refreshToken", data.refresh_Token, {expires: 30});
                setCookie("accessToken", data.access_Token, {expires: ad})
                router.push('/dashboard');
            } else {
                setError('Invalid login credentials');
            }
        } catch (error) {
            console.error('Login failed:', error);
            setError('Invalid login credentials');
        } finally {
            setLoading(false);
        }
    }
    return(
         <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
            <div className="max-w-md w-full space-y-8">
              <div className="text-center">
                <h2 className="mt-6 text-3xl font-bold text-gray-900 dark:text-gray-100">
                Zaloguj się do konta
                </h2>
              </div>

              <div className="mt-8 space-y-6">
                <div className="rounded-md shadow-sm space-y-4">
                <div>
                  <label htmlFor="email" className="sr-only">Email</label>
                  <input
                    id="email"
                    name="email"
                    type="text"
                    ref={email}
                    required
                    className="appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 
                         placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 
                         rounded-md focus:outline-none focus:ring-blue-500 dark:focus:ring-blue-400 
                         focus:border-blue-500 dark:focus:border-blue-400 focus:z-10 sm:text-sm
                         bg-white dark:bg-gray-700"
                    placeholder="Email"
                  />
                </div>
                <div>
                  <label htmlFor="password" className="sr-only">Hasło</label>
                  <input
                    id="password"
                    name="password"
                    type="password"
                    ref={password}
                    required
                    className="appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 
                         placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-gray-100 
                         rounded-md focus:outline-none focus:ring-blue-500 dark:focus:ring-blue-400 
                         focus:border-blue-500 dark:focus:border-blue-400 focus:z-10 sm:text-sm
                         bg-white dark:bg-gray-700"
                    placeholder="Hasło"
                  />
                </div>
                </div>

                <div className="text-center">
                <button
                  onClick={login}
                  disabled={loading}
                  className="group relative w-full mb-4 flex justify-center py-2 px-4 border border-transparent
                         text-sm font-medium rounded-md text-white bg-blue-600 dark:bg-blue-500
                         hover:bg-blue-700 dark:hover:bg-blue-600
                         focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 dark:focus:ring-offset-gray-900"
                >
                  {loading ? 'Logowanie...' : 'Zaloguj się'}
                </button>

                <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300 dark:border-gray-600" />
                  </div>
                  <div className="relative flex justify-center text-xs">
                    <span className="px-2 bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400">lub</span>
                  </div>
                </div>

                <a
                  href={`${process.env.NEXT_PUBLIC_SPICEAUTH_URL}/api/oauth/external/discord/login`}
                  className="w-full mb-8 flex items-center justify-center gap-3 py-2 px-4 border border-transparent
                         text-sm font-medium rounded-md text-white bg-[#5865F2] hover:bg-[#4752C4] transition-colors"
                >
                  <svg width="18" height="18" viewBox="0 0 127.14 96.36" fill="currentColor" aria-hidden>
                    <path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,46,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,46,96.12,53,91.08,65.69,84.69,65.69Z" />
                  </svg>
                  Zaloguj się przez Discord
                </a>

                <Link href="/register" className="mt-5 text-blue-600 dark:text-blue-500
                         hover:text-blue-700 dark:hover:text-blue-600">Nie masz konta? Zarejestruj się tutaj.</Link>
                <br/>
                <Link href="/forgotPassword" className="mt-5 text-blue-600 dark:text-blue-500
                         hover:text-blue-700 dark:hover:text-blue-600">Zapomniałeś hasła?</Link>


                </div>
                {error && (
                    <div className="text-red-600 dark:text-red-400 text-sm text-center">
                        {error}
                    </div>
                )}
                {loading && (
                    <Loading />
                )}
              </div>
            </div>
            </div>
    )
}