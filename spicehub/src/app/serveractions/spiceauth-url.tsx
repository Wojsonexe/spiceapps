'use server'

export async function getSpiceAuthUrl() {
    return process.env.SPICEAUTH_URL
}
