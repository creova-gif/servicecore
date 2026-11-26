import { useEffect } from "react";

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tagName = target.tagName;
  if (tagName === "INPUT" || tagName === "TEXTAREA" || tagName === "SELECT") {
    return true;
  }
  if (target.isContentEditable) {
    return true;
  }
  return Boolean(target.closest("[data-editor]"));
}

export interface UseAuditKeyboardShortcutsOptions {
  isEditing: boolean;
  isRejecting: boolean;
  drawerOpen: boolean;
  helpOpen: boolean;
  canUndo: boolean;
  onNext: () => void;
  onPrev: () => void;
  onApprove: () => void;
  onStartReject: () => void;
  onEnterEdit: () => void;
  onSaveEdit: () => void;
  onCancelEdit: () => void;
  onCancelReject: () => void;
  onCloseDrawer: () => void;
  onToggleHelp: () => void;
  onCloseHelp: () => void;
  onUndo: () => void;
}

/**
 * Global keyboard-first triage shortcut handler (`j`, `k`, `a`, `e`, `r`, `u`, `?`,
 * `Escape`, and Cmd/Ctrl+Enter while editing).
 */
export function useAuditKeyboardShortcuts({
  isEditing,
  isRejecting,
  drawerOpen,
  helpOpen,
  canUndo,
  onNext,
  onPrev,
  onApprove,
  onStartReject,
  onEnterEdit,
  onSaveEdit,
  onCancelEdit,
  onCancelReject,
  onCloseDrawer,
  onToggleHelp,
  onCloseHelp,
  onUndo,
}: UseAuditKeyboardShortcutsOptions): void {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (helpOpen) {
          event.preventDefault();
          onCloseHelp();
          return;
        }
        if (isEditing) {
          event.preventDefault();
          onCancelEdit();
          return;
        }
        if (isRejecting) {
          event.preventDefault();
          onCancelReject();
          return;
        }
        if (drawerOpen) {
          event.preventDefault();
          onCloseDrawer();
          return;
        }
      }

      if (isEditing && (event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        onSaveEdit();
        return;
      }

      if (isEditableTarget(event.target)) {
        return;
      }

      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      if (event.key === "?") {
        event.preventDefault();
        onToggleHelp();
        return;
      }

      if (helpOpen) {
        return;
      }

      switch (event.key.toLowerCase()) {
        case "j":
          event.preventDefault();
          onNext();
          break;
        case "k":
          event.preventDefault();
          onPrev();
          break;
        case "a":
          event.preventDefault();
          onApprove();
          break;
        case "r":
          event.preventDefault();
          onStartReject();
          break;
        case "e":
          event.preventDefault();
          onEnterEdit();
          break;
        case "u":
          if (canUndo) {
            event.preventDefault();
            onUndo();
          }
          break;
        default:
          break;
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    isEditing,
    isRejecting,
    drawerOpen,
    helpOpen,
    canUndo,
    onNext,
    onPrev,
    onApprove,
    onStartReject,
    onEnterEdit,
    onSaveEdit,
    onCancelEdit,
    onCancelReject,
    onCloseDrawer,
    onToggleHelp,
    onCloseHelp,
    onUndo,
  ]);
}
