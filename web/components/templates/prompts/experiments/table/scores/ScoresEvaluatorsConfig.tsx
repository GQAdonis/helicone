import { Col, Row } from "@/components/layout/common";
import { CreateNewEvaluatorSheetContent } from "@/components/shared/CreateNewEvaluator/CreateNewEvaluatorSheetContent";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectItemRawNotText,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Sheet } from "@/components/ui/sheet";
import { useExperimentScores } from "@/services/hooks/prompts/experiment-scores";
import { CheckIcon, Loader2, TriangleAlertIcon, XIcon } from "lucide-react";
import { memo, useState, useEffect } from "react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { useQueryClient } from "@tanstack/react-query";
import { ISLAND_MARGIN } from "@/components/ui/islandContainer";
import { cn } from "@/lib/utils";

const ScoresEvaluatorsConfig = memo(
  ({ experimentId }: { experimentId: string }) => {
    const {
      evaluators,
      addEvaluator,
      removeEvaluator,
      runEvaluators,
      allEvaluators,
      shouldRunEvaluators,
    } = useExperimentScores(experimentId);

    const [open, setOpen] = useState<boolean>(false);
    const [value, setValue] = useState<string>("");

    const queryClient = useQueryClient();

    const [showSuccess, setShowSuccess] = useState(false);
    const [showError, setShowError] = useState(false);

    useEffect(() => {
      if (runEvaluators.isSuccess) {
        setShowSuccess(true);
        const timer = setTimeout(() => setShowSuccess(false), 3000);
        return () => clearTimeout(timer);
      }
    }, [runEvaluators.isSuccess]);

    useEffect(() => {
      if (runEvaluators.isError) {
        setShowError(true);
        const timer = setTimeout(() => setShowError(false), 3000);
        return () => clearTimeout(timer);
      }
    }, [runEvaluators.isError]);

    return (
      <Row className={cn("gap-2 items-center w-full", ISLAND_MARGIN, "mx-6")}>
        <Select
          value={value}
          onValueChange={(value) => {
            if (value === "helicone-new-custom") {
              // addEvaluator.mutate(value);/
              setOpen(true);
              setValue("");
            } else {
              addEvaluator.mutate(value);
              setValue("");
            }
          }}
        >
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="Select an evaluator" />
          </SelectTrigger>

          <SelectContent>
            <SelectItem
              className="cursor-default gap-2 px-2 text-xs"
              value={"helicone-new-custom"}
            >
              Create New Custom Evaluator
            </SelectItem>

            {/* <SelectSeparator /> */}
            <SelectGroup>
              {allEvaluators?.data?.data &&
                allEvaluators.data.data.filter(
                  (evaluator) =>
                    !evaluators?.data?.data?.filter(
                      (e) => e.id === evaluator.id
                    ).length
                )?.length > 0 && (
                  <SelectLabel className="text-xs font-medium text-slate-500 px-2 py-1">
                    Existing Evaluators
                  </SelectLabel>
                )}

              {allEvaluators?.data?.data
                ?.filter(
                  (evaluator) =>
                    !evaluators?.data?.data?.filter(
                      (e) => e.id === evaluator.id
                    ).length
                )
                .map((evaluator) => (
                  <SelectItemRawNotText
                    key={evaluator.id}
                    value={evaluator.id}
                    className="px-2 text-xs"
                    showIndicator={false}
                  >
                    {evaluator.name} ({evaluator.scoring_type})
                  </SelectItemRawNotText>
                ))}
            </SelectGroup>
          </SelectContent>
        </Select>

        <Sheet open={open} onOpenChange={setOpen}>
          <CreateNewEvaluatorSheetContent
            onSubmit={(evaluatorId) => {
              addEvaluator.mutate(evaluatorId);
              setOpen(false);
            }}
            hideButton={true}
          />
        </Sheet>

        <ScrollArea className="flex-1">
          <div className="flex gap-2 justify-start items-start">
            {evaluators?.data?.data?.map((evaluator, index) => {
              return (
                <Badge
                  key={`evaluator-${evaluator.id}-${index}`}
                  variant="helicone"
                  className="gap-1 text-xs text-nowrap whitespace-nowrap items-center cursor-pointer"
                  onClick={() => {
                    removeEvaluator.mutate(evaluator.id);
                  }}
                >
                  <XIcon
                    className="w-3 h-3 cursor-pointer"
                    onClick={(e) => {
                      e.stopPropagation();
                      removeEvaluator.mutate(evaluator.id);
                    }}
                  />
                  <span className="leading-tight">{evaluator.name}</span>
                </Badge>
              );
            })}
          </div>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
        <Col className="items-end">
          <div className="flex items-center gap-2">
            {shouldRunEvaluators.data && (
              <Badge
                variant="helicone"
                className="gap-2 bg-yellow-50 dark:bg-yellow-950 border-yellow-200 dark:border-yellow-800 text-yellow-500 text-xs"
              >
                <TriangleAlertIcon className="w-3 h-3" />
                <span>For latest scores, re-run evaluators</span>
              </Badge>
            )}
            {showSuccess && (
              <Badge
                variant="helicone"
                className="gap-2 bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800 text-green-500 text-xs"
              >
                <CheckIcon className="w-3 h-3" />
                <span>Evaluators ran successfully</span>
              </Badge>
            )}
            {showError && (
              <Badge
                variant="helicone"
                className="gap-2 bg-red-50 dark:bg-red-950 border-red-200 dark:border-red-800 text-red-500 text-xs"
              >
                <TriangleAlertIcon className="w-3 h-3" />
                <span>Error running evaluators</span>
              </Badge>
            )}
            <Button
              size="sm"
              variant={"outline"}
              onClick={() => runEvaluators.mutate()}
              disabled={runEvaluators.isLoading}
              className="text-xs"
            >
              {runEvaluators.isLoading ? "Running..." : "Run Evaluators"}
              {runEvaluators.isLoading && (
                <Loader2 className="w-4 h-4 animate-spin" />
              )}
            </Button>
          </div>
        </Col>
      </Row>
    );
  }
);

ScoresEvaluatorsConfig.displayName = "ScoresEvaluatorsConfig";

export default ScoresEvaluatorsConfig;
