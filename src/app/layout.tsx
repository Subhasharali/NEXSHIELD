import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'NEXSHIELD — Blue-Team AI Firewall for Banking',
  description:
    'High-assurance blue-team AI firewall protecting conversational banking applications from prompt injections, jailbreaks, malicious payment memos, obfuscations, and ambiguous transfers.',
  icons: {
    icon: [
      {
        url: '/icon-light-32x32.png',
        media: '(prefers-color-scheme: light)',
      },
      {
        url: '/icon-dark-32x32.png',
        media: '(prefers-color-scheme: dark)',
      },
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
    apple: '/apple-icon.png',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="cyber-bg">
        <div className="cyber-grid-overlay" />
        {children}
      </body>
    </html>
  );
}
