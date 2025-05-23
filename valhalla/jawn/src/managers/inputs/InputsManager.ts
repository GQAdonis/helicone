// src/users/usersService.ts
import { randomUUID } from "crypto";
import { PromptInputRecord } from "../../controllers/public/promptController";
import { dbExecute } from "../../lib/shared/db/dbExecute";
import { S3Client } from "../../lib/shared/db/s3Client";
import {
  Result,
  err,
  ok,
  promiseResultMap,
} from "../../packages/common/result";
import { RequestResponseBodyStore } from "../../lib/stores/request/RequestResponseBodyStore";
import { BaseManager } from "../BaseManager";

async function fetchImageAsBase64(url: string): Promise<string> {
  try {
    const response = await fetch(url);
    const arrayBuffer = await response.arrayBuffer(); // Get response as ArrayBuffer
    const buffer = Buffer.from(arrayBuffer); // Convert ArrayBuffer to Buffer
    const base64 = buffer.toString("base64"); // Convert Buffer to Base64
    return `data:image/jpeg;base64,${base64}`; // Assuming image is JPEG
  } catch (error) {
    console.error("Failed to fetch or convert image", error);
    throw new Error("Failed to fetch or convert image");
  }
}

export async function getAllSignedURLsFromInputs(
  inputs: PromptInputRecord["inputs"],
  organizationId: string,
  sourceRequest: string,
  replaceAssetWithContent: boolean = false
) {
  const s3Client = new S3Client(
    process.env.S3_ACCESS_KEY ?? "",
    process.env.S3_SECRET_KEY ?? "",
    process.env.S3_ENDPOINT ?? "",
    process.env.S3_BUCKET_NAME ?? "",
    (process.env.S3_REGION as "us-west-2" | "eu-west-1") ?? "us-west-2"
  );

  const result = await Promise.all(
    Object.entries(inputs).map(async ([key, value]) => {
      if (value.includes("helicone-asset-id")) {
        const regex = /<helicone-asset-id key="([^"]+)"\s*\/>/g;
        const heliconeAssetIdKey = regex.exec(value)![1];
        const signedUrl = await s3Client.getRequestResponseImageSignedUrl(
          organizationId,
          sourceRequest,
          heliconeAssetIdKey
        );

        if (replaceAssetWithContent && signedUrl.data) {
          console.log("REPLACING ASSET WITH CONTENT", signedUrl.data);

          // image content
          const contentResponse = await fetchImageAsBase64(signedUrl.data);

          return {
            key,
            value: contentResponse,
          };
        }

        return {
          key,
          value: signedUrl.data ?? "",
        };
      }
      return { key, value };
    })
  );

  return result.reduce((acc, { key, value }) => {
    return {
      ...acc,
      [key]: value,
    };
  }, {} as PromptInputRecord["inputs"]);
}

export class InputsManager extends BaseManager {
  async createInputRecord(
    promptVersionId: string,
    inputs: Record<string, string>,
    sourceRequest?: string,
    experimentId?: string
  ): Promise<Result<string, string>> {
    const inputRecordId = randomUUID();

    try {
      const existingPromptResult = await dbExecute<{ id: string }>(
        `SELECT id
         FROM prompts_versions
         WHERE id = $1 
         AND organization = $2
         LIMIT 1`,
        [promptVersionId, this.authParams.organizationId]
      );

      if (
        existingPromptResult.error ||
        !existingPromptResult.data ||
        existingPromptResult.data.length === 0
      ) {
        return err("Prompt version not found");
      }

      const insertQuery = `
        INSERT INTO prompt_input_record (id, inputs, source_request, prompt_version, experiment_id)
        VALUES ($1, $2, $3, $4, $5)
      `;

      const result = await dbExecute<PromptInputRecord>(insertQuery, [
        inputRecordId,
        JSON.stringify(inputs),
        sourceRequest,
        promptVersionId,
        experimentId,
      ]);

      if (result.error) {
        return err(result.error);
      }

      return ok(inputRecordId);
    } catch (error) {
      return err(`Failed to create input record: ${error}`);
    }
  }

  async createInputRecords(
    promptVersionId: string,
    inputs: Record<string, string>[],
    sourceRequest?: string,
    experimentId?: string
  ): Promise<Result<string[], string>> {
    try {
      const existingPromptResult = await dbExecute<{ id: string }>(
        `SELECT id
         FROM prompts_versions
         WHERE id = $1 
         AND organization = $2
         LIMIT 1`,
        [promptVersionId, this.authParams.organizationId]
      );

      if (
        existingPromptResult.error ||
        !existingPromptResult.data ||
        existingPromptResult.data.length === 0
      ) {
        return err("Prompt version not found");
      }

      // Generate UUIDs for each input record
      const inputRecordIds = inputs.map(() => randomUUID());

      // Create the VALUES part of the query dynamically
      const values = inputs
        .map(
          (_, index) =>
            `($${index * 5 + 1}, $${index * 5 + 2}, $${index * 5 + 3}, $${
              index * 5 + 4
            }, $${index * 5 + 5})`
        )
        .join(",");

      // Flatten parameters array
      const params = inputs.flatMap((input, index) => [
        inputRecordIds[index],
        JSON.stringify(input),
        sourceRequest,
        promptVersionId,
        experimentId,
      ]);

      const result = await dbExecute<PromptInputRecord>(
        `
        INSERT INTO prompt_input_record (id, inputs, source_request, prompt_version, experiment_id)
        VALUES ${values}
        RETURNING id
        `,
        params
      );

      if (result.error) {
        return err(result.error);
      }

      return ok(inputRecordIds);
    } catch (error) {
      return err(`Failed to create input records: ${error}`);
    }
  }

  async updateInputRecord(
    inputRecordId: string,
    inputs: Record<string, string>
  ): Promise<Result<string, string>> {
    const updateQuery = `
      UPDATE prompt_input_record
      SET inputs = COALESCE(inputs, '{}'::jsonb) || $1::jsonb
      WHERE id = $2
      RETURNING id
    `;

    const result = await dbExecute<{ id: string }>(updateQuery, [
      JSON.stringify(inputs),
      inputRecordId,
    ]);

    if (result.error || !result.data?.[0]?.id) {
      return err(result.error ?? "Failed to update input record");
    }

    return ok(result.data?.[0]?.id ?? "");
  }

  async getInputsFromDataset(
    datasetId: string,
    limit: number
  ): Promise<Result<PromptInputRecord[], string>> {
    const bodyStore = new RequestResponseBodyStore(
      this.authParams.organizationId
    );
    const result = await dbExecute<PromptInputRecord>(
      `
      SELECT
        prompt_input_record.id as id,
        experiment_dataset_v2_row.id as dataset_row_id,
        prompt_input_record.inputs as inputs,
        prompt_input_record.auto_prompt_inputs as auto_prompt_inputs,
        prompt_input_record.source_request as source_request,
        prompt_input_record.prompt_version as prompt_version,
        prompt_input_record.created_at as created_at
      FROM experiment_dataset_v2_row 
        left join helicone_dataset on experiment_dataset_v2_row.dataset_id = helicone_dataset.id
        left join prompt_input_record on experiment_dataset_v2_row.input_record = prompt_input_record.id
      WHERE helicone_dataset.organization = $1 AND
      experiment_dataset_v2_row.dataset_id = $2
      ORDER BY experiment_dataset_v2_row.created_at ASC
      LIMIT $3

      `,
      [this.authParams.organizationId, datasetId, limit]
    );
    return promiseResultMap(result, async (data) => {
      return Promise.all(
        data.map(async (record) => {
          const requestResponseBody = await bodyStore.getRequestResponseBody(
            record.source_request
          );
          return {
            ...record,
            inputs: await getAllSignedURLsFromInputs(
              record.inputs,
              this.authParams.organizationId,
              record.source_request
            ),
            response_body: requestResponseBody.data?.response,
            request_body: requestResponseBody.data?.request,
          };
        })
      );
    });
  }

  async getInputsFromPromptVersionAndDataset(
    promptVersion: string,
    datasetId: string
  ): Promise<Result<PromptInputRecord[], string>> {
    console.log(this.authParams.organizationId, promptVersion, datasetId);
    const result = await dbExecute<PromptInputRecord>(
      `
      SELECT
        prompt_input_record.id as id,
        prompt_input_record.inputs as inputs,
        prompt_input_record.auto_prompt_inputs as auto_prompt_inputs,
        prompt_input_record.source_request as source_request,
        prompt_input_record.prompt_version as prompt_version,
        prompt_input_record.created_at as created_at,
        response.body as response_body
      FROM prompt_input_record
      left join request on prompt_input_record.source_request = request.id
      left join response on response.request = request.id
      left join helicone_dataset_row hdr on hdr.origin_request_id = prompt_input_record.source_request
      WHERE  request.helicone_org_id = $1 AND
      prompt_input_record.prompt_version = $2 AND
      hdr.dataset_id = $3
      `,
      [this.authParams.organizationId, promptVersion, datasetId]
    );
    console.log("result", result);
    const bodyStore = new RequestResponseBodyStore(
      this.authParams.organizationId
    );

    return promiseResultMap(result, async (data) => {
      return Promise.all(
        data.map(async (record) => {
          const requestResponseBody = await bodyStore.getRequestResponseBody(
            record.source_request
          );
          return {
            ...record,
            response_body: requestResponseBody.data?.response ?? {},
            request_body: requestResponseBody.data?.request ?? {},
            inputs: await getAllSignedURLsFromInputs(
              record.inputs,
              this.authParams.organizationId,
              record.source_request
            ),
          };
        })
      );
    });
  }
  async getInputs(
    limit: number,
    promptVersion: string,
    random?: boolean
  ): Promise<Result<PromptInputRecord[], string>> {
    const result = await dbExecute<PromptInputRecord>(
      `
      SELECT
        prompt_input_record.id as id,
        prompt_input_record.inputs as inputs,
        prompt_input_record.auto_prompt_inputs as auto_prompt_inputs,
        prompt_input_record.source_request as source_request,
        prompt_input_record.prompt_version as prompt_version,
        prompt_input_record.created_at as created_at,
        response.body as response_body
      FROM prompt_input_record
      left join request on prompt_input_record.source_request = request.id
      left join response on response.request = request.id
      WHERE  request.helicone_org_id = $1 AND
      prompt_input_record.prompt_version = $2
      ${
        random
          ? "ORDER BY random()"
          : "ORDER BY prompt_input_record.created_at DESC"
      }
      LIMIT $3

      `,
      [this.authParams.organizationId, promptVersion, limit]
    );
    const bodyStore = new RequestResponseBodyStore(
      this.authParams.organizationId
    );

    return promiseResultMap(result, async (data) => {
      return Promise.all(
        data.map(async (record) => {
          const requestResponseBody = await bodyStore.getRequestResponseBody(
            record.source_request
          );
          return {
            ...record,
            response_body: requestResponseBody.data?.response ?? {},
            request_body: requestResponseBody.data?.request ?? {},
            inputs: await getAllSignedURLsFromInputs(
              record.inputs,
              this.authParams.organizationId,
              record.source_request
            ),
          };
        })
      );
    });
  }
}
