import ScoresGraph from "./ScoresGraph";
import { useExperimentScores } from "@/services/hooks/prompts/experiment-scores";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

export type PromptVersion = {
  id: string;
  metadata: Record<string, any>;
  major_version: number;
  minor_version: number;
};

const ScoresGraphContainer = ({
  experimentId,
  // fetchExperimentHypothesisScores,
  promptVersions,
}: {
  promptVersions: PromptVersion[];
  experimentId: string;
  // fetchExperimentHypothesisScores: (
  //   hypothesisId: string
  // ) => Promise<Record<string, any>>;
}) => {
  // const [scores, setScores] = useState<Record<string, Record<string, any>>>({});
  // const [loading, setLoading] = useState(true);

  const { fetchExperimentHypothesisScores } = useExperimentScores(experimentId);
  const queryClient = useQueryClient();
  const {
    data: scores,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["experimentScores", experimentId],
    queryFn: async () => {
      const scoresData: Record<string, Record<string, any>> = {};

      // Add signal handling to prevent query cancellation
      const results = await Promise.all(
        promptVersions.map(async (promptVersion) => {
          if (promptVersion.id) {
            return {
              id: promptVersion.id,
              data: await fetchExperimentHypothesisScores(promptVersion.id),
            };
          }
        })
      );

      // Process results after Promise.all completes
      results.forEach((result) => {
        if (result) {
          scoresData[result.id] = result.data;
        }
      });

      return scoresData;
    },
    // Add these options to prevent cancellation
    staleTime: 0,
    refetchOnWindowFocus: false,
    onSuccess: (data) => {
      Object.entries(data).forEach(([promptVersionId, score]) => {
        queryClient.setQueryData(
          ["experimentScores", experimentId, promptVersionId],
          score ?? ""
        );
      });
    },
  });

  useEffect(() => {
    refetch();
  }, [promptVersions]);

  if (isLoading) {
    return <div>Loading...</div>; // Or your loading component
  }

  return (
    <ScoresGraph
      promptVersions={promptVersions}
      experimentId={experimentId}
      scores={
        scores as Record<
          string,
          {
            data: Record<string, { value: any; valueType: string }>;

            error: string | null;
          }
        >
      }
    />
  );
};

export default ScoresGraphContainer;
