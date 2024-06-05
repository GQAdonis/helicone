import { Result } from "../shared/result";
import { DBLoggable, dbLoggableRequestFromProxyRequest } from "./DBLoggable";
import { HeliconeProxyRequest } from "./HeliconeProxyRequest";
import {
  callPropsFromProxyRequest,
  callProvider,
  callProviderWithRetry,
} from "./ProviderClient";
import { CompletedChunk, ReadableInterceptor } from "./ReadableInterceptor";
import crypto from "crypto";
import { Response as ExpressResponse } from "express";

export type ProxyResult = {
  loggable: DBLoggable;
  response: ExpressResponse;
};

function getStatus(
  responseStatus: number,
  endReason?: CompletedChunk["reason"]
) {
  if (!endReason) {
    return responseStatus;
  } else if (endReason === "done") {
    return responseStatus;
  } else if (endReason === "cancel") {
    return -3;
  } else if (endReason === "timeout") {
    return -2;
  } else {
    return -100;
  }
}

export async function handleProxyRequest(
  proxyRequest: HeliconeProxyRequest,
  expressRes: ExpressResponse
): Promise<Result<ProxyResult, string>> {
  const { retryOptions } = proxyRequest;

  const requestStartTime = new Date();
  const callProps = callPropsFromProxyRequest(proxyRequest);
  const response = await (retryOptions
    ? callProviderWithRetry(callProps, retryOptions)
    : callProvider(callProps));

  const interceptor = response.body
    ? new ReadableInterceptor(response.body, expressRes, proxyRequest.isStream)
    : null;
  let body = interceptor ? interceptor.stream : null;

  if (
    proxyRequest.requestWrapper.heliconeHeaders.featureFlags.streamForceFormat
  ) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let buffer: any = null;
    const transformer = new TransformStream({
      transform(chunk, controller) {
        if (chunk.length < 50) {
          buffer = chunk;
        } else {
          if (buffer) {
            const mergedArray = new Uint8Array(buffer.length + chunk.length);
            mergedArray.set(buffer);
            mergedArray.set(chunk, buffer.length);
            controller.enqueue(mergedArray);
          } else {
            controller.enqueue(chunk);
          }
          buffer = null;
        }
      },
    });
    body = body?.pipeThrough(transformer) ?? null;
  }

  const responseHeaders = new Headers(response.headers);
  responseHeaders.set("Helicone-Status", "success");
  responseHeaders.set("Helicone-Id", proxyRequest.requestId);

  let status = response.status;
  if (status < 200 || status >= 600) {
    console.error("Invalid status code: ", status);
    status = 500;
    if (status === 100) {
      status = 200;
    }
  }

  responseHeaders.forEach((value, key) => {
    expressRes.setHeader(key, value);
  });

  expressRes.status(status);

  if (interceptor) {
    console.log("Interceptor created, starting stream");
  } else {
    console.log("No interceptor created, ending response");
    expressRes.end();
  }

  return {
    data: {
      loggable: new DBLoggable({
        request: dbLoggableRequestFromProxyRequest(
          proxyRequest,
          requestStartTime
        ),
        response: {
          responseId: crypto.randomUUID(),
          getResponseBody: async () => ({
            body: (await interceptor?.waitForChunk())?.body ?? "",
            endTime: new Date(
              (await interceptor?.waitForChunk())?.endTimeUnix ??
                new Date().getTime()
            ),
          }),
          responseHeaders: new Headers(response.headers),
          status: async () => {
            return getStatus(
              response.status,
              (await interceptor?.waitForChunk())?.reason
            );
          },
          omitLog:
            proxyRequest.requestWrapper.heliconeHeaders.omitHeaders
              .omitResponse,
        },
        timing: {
          startTime: proxyRequest.startTime,
          timeToFirstToken: async () => {
            if (proxyRequest.isStream) {
              const chunk = await interceptor?.waitForChunk();
              const startTimeUnix = proxyRequest.startTime.getTime();
              if (chunk?.firstChunkTimeUnix && startTimeUnix) {
                return chunk.firstChunkTimeUnix - startTimeUnix;
              }
            }

            return null;
          },
        },
        tokenCalcUrl: proxyRequest.tokenCalcUrl,
      }),
      // response: new Response(body, {
      //   ...response,
      //   headers: responseHeaders,
      //   status: status,
      // }),
      // How to do the above, but it has to be an express response???
      response: expressRes,
    },
    error: null,
  };
}