import type { WizardStep } from "@/components/connections/wizard-support";
import { ArrowLeft,ArrowRight,Plus } from "lucide-react";
import type { Dispatch,SetStateAction } from "react";

export function WizardNavigation({ step, setStep, onClose, goNext, submitting }: {
  step: WizardStep;
  setStep: Dispatch<SetStateAction<WizardStep>>;
  onClose: () => void;
  goNext: () => void;
  submitting: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-outline px-5 py-4">
      {step === 3 ? (
        // The connection already exists; going back would re-create it. Verify
        // and first-scan actions live in the panel; the footer only closes.
        <span aria-hidden className="h-9" />
      ) : (
        <button
          type="button"
          onClick={() => (step === 0 ? onClose() : setStep((s) => (s - 1) as WizardStep))}
          className="inline-flex items-center gap-1.5 rounded-xl border border-outline bg-surface-elevated px-4 py-2 text-sm text-foreground transition hover:border-outline-strong"
        >
          {step === 0 ? (
            "Cancel"
          ) : (
            <>
              <ArrowLeft className="h-4 w-4" /> Back
            </>
          )}
        </button>
      )}
      {step < 2 ? (
        <button
          key="wizard-next"
          type="button"
          onClick={goNext}
          className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
        >
          Next <ArrowRight className="h-4 w-4" />
        </button>
      ) : step === 2 ? (
        <button
          key="wizard-submit"
          type="submit"
          disabled={submitting}
          className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <Plus className="h-4 w-4" />
          {submitting ? "Connecting…" : "Create connection"}
        </button>
      ) : (
        <button
          key="wizard-done"
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
        >
          Done
        </button>
      )}
    </div>
  );
}
