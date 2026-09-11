import type { Metadata } from "next";
import { VegaStackProvider } from "@/components/ui/provider";
import { ConsoleQueryProvider } from "@/components/query-provider";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "VegaStack Labs Console", template: "%s — VegaStack Labs Console" },
  description: "Credential-free static Console foundation for VegaStack Labs.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans text-foreground antialiased">
        <VegaStackProvider><ConsoleQueryProvider>{children}</ConsoleQueryProvider></VegaStackProvider>
      </body>
    </html>
  );
}
