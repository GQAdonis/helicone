import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { RabbitIcon, TurtleIcon } from "lucide-react";

const OnboardingDemoModal = ({
  open,
  setOpen,
  quickStart,
  quickTour,
}: {
  open: boolean;
  setOpen: (open: boolean) => void;
  quickStart: () => void;
  quickTour: () => void;
}) => {
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="w-11/12 sm:max-w-2xl gap-8 rounded-md">
        <DialogHeader className="space-y-2">
          <DialogTitle>Welcome to Helicone!</DialogTitle>
          <DialogDescription className="text-sm">
            To help you get started, take a tour or integrate with your LLM app.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-4">
          <div
            className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800"
            onClick={quickStart}
          >
            <div className="flex flex-col gap-4">
              <TurtleIcon className="w-6 h-6 text-slate-400 dark:text-slate-500" />
              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium text-slate-900 dark:text-slate-50 leading-4">
                  Quick start{" "}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Integrate with your own LLM app
                </p>
              </div>
            </div>
          </div>
          <div
            className="p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800"
            onClick={quickTour}
          >
            <div className="flex flex-col gap-4">
              <div className="flex justify-between items-center">
                <RabbitIcon className="w-6 h-6 text-blue-500" />

                <div className="px-3 py-1 rounded-md bg-blue-100 text-blue-700 text-xs font-semibold uppercase">
                  NEW
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <h3 className="text-sm font-medium text-slate-900 dark:text-slate-50 leading-4">
                  Take a quick tour
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Get a feel of what Helicone has to offer.
                </p>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default OnboardingDemoModal;