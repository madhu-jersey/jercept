/**
 * Jercept LLM extractor — tier 3 of the 3-tier pipeline.
 *
 * Calls an LLM to extract a scope when fast regex doesn't match.
 * Supports OpenAI, Anthropic, and Ollama.
 */

import { IBACScope, createScope } from "./scope.js";

export type LLMProvider = "openai" | "anthropic" | "ollama";

export interface ExtractorOptions {
  /** LLM provider. Default: "openai" */
  provider?: LLMProvider;
  /** Model name. Defaults per provider: gpt-4o-mini / claude-3-haiku-20240307 / llama3 */
  model?: string;
  /** API key. Falls back to OPENAI_API_KEY / ANTHROPIC_API_KEY env var. */
  apiKey?: string;
  /** Ollama base URL. Default: http://localhost:11434 */
  ollamaBaseUrl?: string;
}

const SYSTEM_PROMPT = `You are a security policy engine for AI agents.
Given a user's natural language request, extract the minimal
permission scope needed to fulfill it safely.

SECURITY PRINCIPLE: Deny everything not explicitly required.
Default to the most restrictive scope possible.

Return ONLY valid JSON, no explanation, no markdown:
{
  "allowed_actions": ["db.read"],
  "allowed_resources": ["customer#123"],
  "denied_actions": ["db.export", "db.write", "db.delete",
                     "file.write", "file.download", "code.execute",
                     "email.send", "web.browse"],
  "confidence": 0.95,
  "ambiguous": false
}

ACTION TAXONOMY:
db.read, db.write, db.export, db.delete
file.read, file.write, file.upload, file.download
email.read, email.send
api.call, web.browse, code.execute

AMBIGUITY RULE: If the request does not clearly specify what action
is needed, set ambiguous=true and allowed_actions=[] and confidence=0.0`;

const MIN_CONFIDENCE = 0.5;

export class IBACExtractionError extends Error {
  constructor(
    public readonly reason: string,
    public readonly originalRequest: string,
  ) {
    super(`IBACExtractionFailed: ${reason}`);
    this.name = "IBACExtractionError";
  }
}

async function callOpenAI(request: string, opts: ExtractorOptions): Promise<string> {
  const model = opts.model ?? "gpt-4o-mini";
  const apiKey = opts.apiKey ?? process.env["OPENAI_API_KEY"];
  if (!apiKey) throw new IBACExtractionError("No OpenAI API key. Set OPENAI_API_KEY.", request);

  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0,
      max_tokens: 400,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: request },
      ],
    }),
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new IBACExtractionError(`OpenAI API error ${resp.status}: ${err.slice(0, 200)}`, request);
  }
  const data = await resp.json() as { choices: Array<{ message: { content: string } }> };
  return data.choices[0]?.message?.content ?? "";
}

async function callAnthropic(request: string, opts: ExtractorOptions): Promise<string> {
  const model = opts.model ?? "claude-3-haiku-20240307";
  const apiKey = opts.apiKey ?? process.env["ANTHROPIC_API_KEY"];
  if (!apiKey) throw new IBACExtractionError("No Anthropic API key. Set ANTHROPIC_API_KEY.", request);

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 400,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: request }],
    }),
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new IBACExtractionError(`Anthropic API error ${resp.status}: ${err.slice(0, 200)}`, request);
  }
  const data = await resp.json() as { content: Array<{ text: string }> };
  return data.content[0]?.text ?? "";
}

async function callOllama(request: string, opts: ExtractorOptions): Promise<string> {
  const model = opts.model ?? "llama3";
  const base = (opts.ollamaBaseUrl ?? "http://localhost:11434").replace(/\/$/, "");
  const prompt = `${SYSTEM_PROMPT}\n\nUser request: ${request}\n\nReturn ONLY valid JSON:`;

  const resp = await fetch(`${base}/api/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, prompt, stream: false, options: { temperature: 0, num_predict: 400 } }),
  });
  if (!resp.ok) {
    throw new IBACExtractionError(
      `Ollama not reachable at ${base}. Is Ollama running? (ollama serve)`, request
    );
  }
  const data = await resp.json() as { response: string };
  return data.response ?? "";
}

function parseJSON(raw: string, request: string): Record<string, unknown> {
  let text = raw.trim();
  // Strip markdown fences
  if (text.startsWith("```")) {
    text = text.split("```")[1] ?? "";
    if (text.startsWith("json")) text = text.slice(4);
    text = text.trim();
  }
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new IBACExtractionError(
      `LLM returned non-JSON: ${text.slice(0, 200)}`, request
    );
  }
}

/**
 * Extract an IBACScope from a user request using an LLM.
 *
 * Retries up to 3 times with exponential backoff on transient errors.
 * Authentication errors are not retried.
 *
 * @param request - The user's natural language request.
 * @param opts - Provider options (provider, model, apiKey).
 * @returns IBACScope with extracted permissions.
 * @throws IBACExtractionError if extraction fails or request is ambiguous.
 *
 * @example
 * ```ts
 * const scope = await llmExtract("check billing for customer 123");
 * // scope.allowedActions === ["db.read"]
 *
 * // With Anthropic
 * const scope2 = await llmExtract("send email", { provider: "anthropic" });
 *
 * // With local Ollama
 * const scope3 = await llmExtract("run script", { provider: "ollama", model: "llama3" });
 * ```
 */
export async function llmExtract(
  request: string,
  opts: ExtractorOptions = {},
): Promise<IBACScope> {
  const provider = opts.provider ?? "openai";
  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      let raw: string;
      if (provider === "openai")    raw = await callOpenAI(request, opts);
      else if (provider === "anthropic") raw = await callAnthropic(request, opts);
      else if (provider === "ollama")    raw = await callOllama(request, opts);
      else throw new IBACExtractionError(`Unknown provider: ${provider}`, request);

      const data = parseJSON(raw, request);
      const confidence = Number(data["confidence"] ?? 0);
      const ambiguous  = Boolean(data["ambiguous"] ?? false);

      if (ambiguous || confidence < MIN_CONFIDENCE) {
        throw new IBACExtractionError(
          `Request too ambiguous (confidence=${confidence.toFixed(2)}, ambiguous=${ambiguous})`,
          request
        );
      }

      return createScope({
        allowedActions:  (data["allowed_actions"]   as string[]) ?? [],
        allowedResources: (data["allowed_resources"] as string[]) ?? [],
        deniedActions:   (data["denied_actions"]    as string[]) ?? [],
        rawIntent:       request,
        confidence,
        ambiguous:       false,
      });

    } catch (err) {
      lastError = err as Error;
      // Don't retry auth errors or ambiguity errors
      if (err instanceof IBACExtractionError) {
        if (err.reason.includes("ambiguous") || err.reason.includes("API key") ||
            err.reason.includes("not reachable")) {
          throw err;
        }
      }
      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
      }
    }
  }
  throw lastError ?? new IBACExtractionError("Unknown extraction failure", request);
}
