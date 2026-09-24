export const phase5PrivateCanaries: ReadonlyArray<string>;
export function assertPrivacyEvidence(value: unknown, needles: ReadonlyArray<string>, surface: string): void;
export function captureVisibleBrowserEvidence(page: import("@playwright/test").Page, consoleMessages: string[]): Promise<unknown>;
