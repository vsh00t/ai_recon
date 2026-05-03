import type { Metadata } from "next";
import "@/styles/globals.css";
import { Providers } from "@/lib/providers";

export const metadata: Metadata = {
  title: "ai-recon",
  description: "Universal AI reconnaissance and red-teaming framework",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
