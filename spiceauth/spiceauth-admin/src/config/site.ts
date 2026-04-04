export const siteConfig = {
    name: "SpiceAuth Admin",
    description: "OAuth2 Authorization Server Admin Panel",
    url: process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000",
    apiUrl: process.env.NEXT_PUBLIC_API_URL || "https://localhost:5001",
    links: {
        github: "https://github.com/yourusername/spiceauth",
        docs: "https://docs.spiceauth.com",
    },
};
