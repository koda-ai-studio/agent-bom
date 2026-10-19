"use client";

import Link from "next/link";
import type { ElementType } from "react";
import { useEffect, useRef, useState } from "react";
import { Search } from "lucide-react";

import { searchEstateEntities, type EntitySearchResult } from "@/lib/command-entity-search";

const ENTITY_SEARCH_DEBOUNCE_MS = 250;
const ENTITY_SEARCH_MIN_CHARS = 2;

export interface CommandPaletteLink {
  href: string;
  label: string;
  group: string;
  icon: ElementType;
}

export interface CommandPaletteAction {
  id: string;
  label: string;
  group: string;
  icon: ElementType;
  run: () => void;
  keywords?: string[];
}

interface CommandPaletteProps {
  query: string;
  links: CommandPaletteLink[];
  actions?: CommandPaletteAction[];
  setQuery: (query: string) => void;
  onClose: () => void;
  /** Entity lookup over the current estate; injectable for tests. */
  searchEntities?: (query: string) => Promise<EntitySearchResult[]>;
}

type EntityState = { query: string; status: "idle" | "loading" | "done" | "error"; results: EntitySearchResult[] };

function useEntitySearch(query: string, search: (query: string) => Promise<EntitySearchResult[]>): EntityState {
  const [state, setState] = useState<EntityState>({ query: "", status: "idle", results: [] });
  const latest = useRef(0);
  const trimmed = query.trim();
  useEffect(() => {
    const request = ++latest.current;
    if (trimmed.length < ENTITY_SEARCH_MIN_CHARS) {
      setState({ query: trimmed, status: "idle", results: [] });
      return;
    }
    setState((current) => ({ ...current, query: trimmed, status: "loading" }));
    const timer = window.setTimeout(() => {
      search(trimmed).then(
        (results) => { if (latest.current === request) setState({ query: trimmed, status: "done", results }); },
        () => { if (latest.current === request) setState({ query: trimmed, status: "error", results: [] }); },
      );
    }, ENTITY_SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [search, trimmed]);
  return state;
}

function matchesQuery(query: string, label: string, group: string, keywords: string[] = []) {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [label, group, ...keywords].some((value) => value.toLowerCase().includes(q));
}

export function CommandPalette({ query, links, actions = [], setQuery, onClose, searchEntities = searchEstateEntities }: CommandPaletteProps) {
  const filteredLinks = links.filter((link) => matchesQuery(query, link.label, link.group));
  const filteredActions = actions.filter((action) => matchesQuery(query, action.label, action.group, action.keywords));
  const entities = useEntitySearch(query, searchEntities);
  const hasResults = filteredLinks.length > 0 || filteredActions.length > 0 || entities.results.length > 0;
  const entityPending = entities.status === "loading";

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]" role="dialog" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg overflow-hidden rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] shadow-2xl">
        <div className="flex items-center gap-3 border-b border-[color:var(--border-subtle)] px-4 py-3">
          <Search className="h-4 w-4 shrink-0 text-[color:var(--text-secondary)]" />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search pages, CVEs, agents, packages..."
            className="flex-1 bg-transparent text-sm text-[color:var(--foreground)] outline-none placeholder:text-[color:var(--text-secondary)]"
          />
          <kbd className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-[color:var(--text-secondary)]">
            ESC
          </kbd>
        </div>
        <div className="max-h-[50vh] overflow-y-auto py-2">
          {entities.status === "error" ? (
            <p role="status" className="px-4 py-2 text-xs text-[color:var(--text-secondary)]">Entity search is unavailable right now; page and command results still work.</p>
          ) : entityPending ? (
            <p role="status" className="px-4 py-2 text-xs text-[color:var(--text-tertiary)]">Searching the current estate…</p>
          ) : null}
          {!hasResults ? (
            entityPending ? null : <div className="px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">No results found</div>
          ) : (
            <>
              {entities.results.map(({ key, href, label, kind }) => (
                <Link
                  key={key}
                  href={href}
                  onClick={onClose}
                  className="flex items-center gap-3 px-4 py-2.5 text-sm text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-elevated)]"
                >
                  <Search className="h-4 w-4 shrink-0 text-[color:var(--text-secondary)]" />
                  <span className="min-w-0 flex-1 truncate">{label}</span>
                  <span className="text-[10px] uppercase tracking-wider text-[color:var(--text-tertiary)]">{kind}</span>
                </Link>
              ))}
              {filteredActions.map(({ id, label, icon: Icon, group, run }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => {
                    run();
                    onClose();
                  }}
                  className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-elevated)]"
                >
                  <Icon className="h-4 w-4 shrink-0 text-[color:var(--text-secondary)]" />
                  <span className="flex-1">{label}</span>
                  <span className="text-[10px] uppercase tracking-wider text-[color:var(--text-tertiary)]">{group}</span>
                </button>
              ))}
              {filteredLinks.map(({ href, label, icon: Icon, group }) => (
                <Link
                  key={href}
                  href={href}
                  onClick={onClose}
                  className="flex items-center gap-3 px-4 py-2.5 text-sm text-[color:var(--foreground)] transition-colors hover:bg-[color:var(--surface-elevated)]"
                >
                  <Icon className="h-4 w-4 shrink-0 text-[color:var(--text-secondary)]" />
                  <span className="flex-1">{label}</span>
                  <span className="text-[10px] uppercase tracking-wider text-[color:var(--text-tertiary)]">{group}</span>
                </Link>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
