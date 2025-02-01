/**
 *
 * DO NOT EDIT THIS FILE UNLESS IT IS IN /costs/src/index.ts
 */

import { ModelRow } from "./interfaces/Cost";
import { allCosts, defaultProvider, providers } from "./providers/mappings";

export function costOf({
  model,
  provider,
}: {
  model: string;
  provider: string;
}) {
  const modelLower = model?.toLowerCase();

  if (!modelLower) {
    return null;
  }

  const providerCost = providers.find((p) => {
    return (
      p.provider === provider ||
      (p.pattern && p.pattern.test(provider) ? true : false)
    );
  });

  if (!providerCost || !providerCost.costs) {
    return null;
  }

  // We need to concat allCosts because we need to check the provider costs first and if it is not founder thn fall back to make the best guess.
  // This is because we did not backfill the provider on supabase yet, and we do not plan to
  // This is really for legacy
  // TODO after 07/2024 we can probably remove this
  const costs = providerCost.costs.concat(allCosts);

  const cost = costs.find((cost) => {
    const valueLower = cost.model.value.toLowerCase();
    if (cost.model.operator === "equals") {
      return valueLower === modelLower;
    } else if (cost.model.operator === "startsWith") {
      return modelLower.startsWith(valueLower);
    } else if (cost.model.operator === "includes") {
      return modelLower.includes(valueLower);
    }
  });

  return cost?.cost;
}

export function costOfPrompt({
  model,
  promptTokens,
  completionTokens,
  provider: provider,
  images = 1,
  perCall = 1,
}: {
  model: string;
  promptTokens: number;
  completionTokens: number;
  provider: string;
  images?: number;
  perCall?: number;
}) {
  const cost = costOf({ model, provider });
  if (!cost) {
    return null;
  }
  const tokenCost =
    cost.prompt_token * promptTokens + cost.completion_token * completionTokens;
  const imageCost = (cost.per_image ?? 0) * images;
  const perCallCost = (cost.per_call ?? 0) * perCall;
  return tokenCost + imageCost + perCallCost;
}

function caseForCost(costs: ModelRow[], table: string, multiple: number) {
  return `
  CASE
  ${costs
    .map((cost) => {
      const costPerMultiple = {
        prompt: Math.round(cost.cost.prompt_token * multiple),
        completion: Math.round(cost.cost.completion_token * multiple),
        image: Math.round((cost.cost.per_image ?? 0) * multiple),
        per_call: Math.round((cost.cost.per_call ?? 0) * multiple),
      };

      const costs = [];
      if (costPerMultiple.prompt > 0) {
        costs.push(`${costPerMultiple.prompt} * ${table}.prompt_tokens`);
      }
      if (costPerMultiple.completion > 0) {
        costs.push(
          `${costPerMultiple.completion} * ${table}.completion_tokens`
        );
      }
      if (costPerMultiple.image > 0) {
        costs.push(`${costPerMultiple.image}`);
      }
      if (costPerMultiple.per_call > 0) {
        costs.push(`${costPerMultiple.per_call}`);
      }

      if (costs.length > 0) {
        const costString = costs.join(" + ");
        if (cost.model.operator === "equals") {
          return `WHEN (${table}.model ILIKE '${cost.model.value}') THEN ${costString}`;
        } else if (cost.model.operator === "startsWith") {
          return `WHEN (${table}.model LIKE '${cost.model.value}%') THEN ${costString}`;
        } else if (cost.model.operator === "includes") {
          return `WHEN (${table}.model ILIKE '%${cost.model.value}%') THEN ${costString}`;
        } else {
          throw new Error("Unknown operator");
        }
      } else {
        return ``;
      }
    })
    .join("\n")}
  ELSE 0
END
`;
}
export const COST_MULTIPLE = 1_000_000_000;
export function clickhousePriceCalc(table: string) {
  // This is so that we don't need to do any floating point math in the database
  // and we can just divide by 1_000_000 to get the cost in dollars

  const providersWithCosts = providers.filter(
    (p) => p.costs && defaultProvider.provider !== p.provider
  );
  if (!defaultProvider.costs) {
    throw new Error("Default provider does not have costs");
  }
  return `
sum(
  CASE
  ${providersWithCosts
    .map((provider) => {
      if (!provider.costs) {
        throw new Error("Provider does not have costs");
      }

      return `WHEN (${table}.provider = '${
        provider.provider
      }') THEN (${caseForCost(provider.costs, table, COST_MULTIPLE)})`;
    })
    .join("\n")}
    ELSE ${caseForCost(defaultProvider.costs, table, COST_MULTIPLE)}
  END
  ) / ${COST_MULTIPLE}
`;
}
