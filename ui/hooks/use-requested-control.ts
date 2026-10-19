import { useEffect, useRef } from "react";

interface Section<C> {
  id: string;
  title: string;
  controls: C[];
  catalog?: Record<string, string> | undefined;
}

/**
 * Open the control a deep link names (``?framework=…&control=…``) once its
 * framework section is selected. Returns whether the named control is missing
 * from that section's assessment, so the page can say so instead of nothing.
 */
export function useRequestedControl<C extends { code: string }>(
  frameworkParam: string,
  controlParam: string,
  section: Section<C> | undefined,
  open: (selection: { control: C; frameworkLabel: string; frameworkId: string; catalog?: Record<string, string> | undefined }) => void,
): boolean {
  const opened = useRef("");
  const applies = Boolean(controlParam && section && section.id === frameworkParam);
  const control = applies ? section!.controls.find((candidate) => candidate.code.toLowerCase() === controlParam.toLowerCase()) : undefined;
  useEffect(() => {
    if (!control || !section) return;
    const key = `${frameworkParam}:${controlParam}`;
    if (opened.current === key) return;
    opened.current = key;
    open({ control, frameworkLabel: section.title, frameworkId: section.id, catalog: section.catalog });
  }, [control, controlParam, frameworkParam, open, section]);
  return applies && !control;
}
