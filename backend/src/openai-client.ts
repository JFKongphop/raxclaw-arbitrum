/*!
OpenAI Client — LLM inference interface for GPT-4o-mini / GPT-4.

OpenAI-compatible chat completions API.
OpenAI-compatible chat completions API for LLM reasoning and report generation.
*/

import OpenAI from "openai";

interface ChatCompletionResponse {
  choices: Array<{ message: { content: string } }>;
}

export class OpenAiClient {
  private client: OpenAI;
  private model: string;

  /** Create from env vars: OPENAI_API_KEY + OPENAI_MODEL (defaults to gpt-4o-mini). */
  static fromEnv(): OpenAiClient {
    const apiKey = process.env["OPENAI_API_KEY"];
    if (!apiKey) throw new Error("OPENAI_API_KEY not set in .env");
    const model = process.env["OPENAI_MODEL"] ?? "gpt-4o-mini";
    return new OpenAiClient(apiKey, model);
  }

  constructor(apiKey: string, model: string) {
    this.client = new OpenAI({ apiKey });
    this.model = model;
  }

  /** Run inference — returns the model's response text. max_tokens = 4096. */
  async infer(prompt: string): Promise<string> {
    return this.inferWithMaxTokens(prompt, 4096);
  }

  /** Run inference with custom max_tokens parameter. */
  async inferWithMaxTokens(prompt: string, maxTokens?: number): Promise<string> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: [
        {
          role: "system",
          content: "You are a smart contract security expert.",
        },
        { role: "user", content: prompt },
      ],
      max_tokens: maxTokens ?? 4096,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) throw new Error("OpenAI returned empty response");
    return content;
  }

  getModel(): string {
    return this.model;
  }
}
