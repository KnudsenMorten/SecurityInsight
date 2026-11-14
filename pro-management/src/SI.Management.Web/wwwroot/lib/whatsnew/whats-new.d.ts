// Types of whats-new.js (WHATS-NEW-1) for Invardia's TypeScript (core, front, site, import tool). The products embed the .js only.
export interface WhatsNewItem { title: string; text: string; action?: string }
export interface WhatsNewFile { $schema?: string; version: string; date: string; type: 'fix-only' | 'feature' | 'security'; summary: string; new: WhatsNewItem[]; fixes: WhatsNewItem[] }
export interface WhatsNewCard {
  version: string; date: string; type: string; typeLabel: string; summary: string;
  actions: string[]; new: WhatsNewItem[]; fixes: WhatsNewItem[];
}
export interface WhatsNewStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
export interface WhatsNewOptions { productName?: string; heading?: boolean; product?: string; storageKey?: string; storage?: WhatsNewStorage | null; markSeen?: boolean }

export declare const WHATS_NEW_LIMITS: Readonly<{ titleWords: number; textWords: number; itemsPerSection: number }>;
export declare const WHATS_NEW_TYPES: Readonly<Record<'feature' | 'fix-only' | 'security', string>>;
export declare const WHATS_NEW_NONE: string;
export declare const WHATS_NEW_EMPTY: string;
export declare const WHATS_NEW_VERSION: RegExp;
export declare function compareWhatsNewVersion(a: string, b: string): number;
export declare function checkWhatsNewFile(raw: unknown): string[];
export declare function whatsNewStyleProblems(raw: unknown): string[];
export declare function whatsNewConformance(raw: unknown): string[];
export declare function sortWhatsNew<T extends object>(files: readonly T[] | null | undefined): T[];
export declare function whatsNewCard(f: WhatsNewFile): WhatsNewCard;
export declare function whatsNewHtml(files: readonly unknown[] | null | undefined, opts?: WhatsNewOptions): string;
export declare function newestWhatsNewVersion(files: readonly unknown[] | null | undefined): string | null;
export declare function shouldShowNewBadge(filesOrVersion: readonly unknown[] | string | null | undefined, opts?: WhatsNewOptions): boolean;
export declare function markWhatsNewSeen(filesOrVersion: readonly unknown[] | string | null | undefined, opts?: WhatsNewOptions): boolean;
export declare function renderWhatsNew(element: { innerHTML: string }, files: readonly unknown[] | null | undefined, opts?: WhatsNewOptions): number;
