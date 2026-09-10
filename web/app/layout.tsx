import type { Metadata } from "next";
import { VegaStackProvider } from "@/components/ui/provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "VegaStack Labs — Development scaffold",
  description: "Credential-free public development scaffold for VegaStack Labs.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <VegaStackProvider>{children}</VegaStackProvider>
      </body>
    </html>
  );
}
