/*!
Qdrant Vector Database Client — fast semantic search for the exploit RAG pipeline.

Qdrant Cloud HNSW-indexed semantic search for the exploit RAG pipeline.
Collections: defi_cases (vulnerability patterns) + defi_protocols (real exploits).

Every point stores a 1536-dim OpenAI embedding plus metadata payload.
Search queries both collections, merges, and returns top-k by score.
*/

import { QdrantClient } from "@qdrant/js-client-rest";

// ─── Shared result type ──────────────────────────────────────────────────────

export interface QdrantExploitResult {
  score: number;
  exploitName: string;
  vulnType: string;
  chain: string;
  date: string;
  totalLost: string;
  source: string;
  codeSnippet: string;
  attackTx: string;
  embeddingDim: number;
  collection: string;
}

interface ExploitPayload {
  exploit_name?: string;
  vuln_type?: string;
  chain?: string;
  date?: string;
  total_lost?: string;
  source?: string;
  code_snippet?: string;
  attack_tx?: string;
  embedding_dim?: number;
}

// ─── Client ───────────────────────────────────────────────────────────────────

export class QdrantStorageClient {
  private client: QdrantClient;
  private collections: string[];

  /** Create a new client from env vars. */
  static fromEnv(): QdrantStorageClient {
    const endpoint = process.env["QDRANT_ENDPOINT"];
    if (!endpoint) throw new Error("QDRANT_ENDPOINT not set in .env");
    const apiKey = process.env["QDRANT_API_KEY"];
    if (!apiKey) throw new Error("QDRANT_API_KEY not set in .env");
    return new QdrantStorageClient(endpoint, apiKey);
  }

  constructor(endpoint: string, apiKey: string) {
    this.client = new QdrantClient({
      url: endpoint.replace(/\/$/, ""),
      apiKey,
    });
    this.collections = ["defi_cases", "defi_protocols"];
  }

  getCollectionNames(): string[] {
    return [...this.collections];
  }

  /** Search both collections, merge by score, return top-k. */
  async query(embedding: number[], topK: number): Promise<QdrantExploitResult[]> {
    const allResults: QdrantExploitResult[] = [];

    for (const collection of this.collections) {
      try {
        const resp = await this.client.search(collection, {
          vector: embedding,
          limit: topK,
          with_payload: true,
        });

        for (const point of resp) {
          const payload = (point.payload ?? {}) as ExploitPayload;
          const score = point.score;
          if (score === undefined || score === null || typeof score !== "number") continue;

          allResults.push({
            score,
            exploitName: payload.exploit_name ?? "Unknown",
            vulnType: payload.vuln_type ?? "Unknown",
            chain: payload.chain ?? "Unknown",
            date: payload.date ?? "N/A",
            totalLost: payload.total_lost ?? "N/A",
            source: payload.source ?? "Unknown",
            codeSnippet: payload.code_snippet ?? "N/A",
            attackTx: payload.attack_tx ?? "",
            embeddingDim: payload.embedding_dim ?? 1536,
            collection,
          });
        }
      } catch (e) {
        console.error(
          `[Qdrant]   Collection '${collection}' search failed:`,
          (e as Error).message.slice(0, 200),
        );
      }
    }

    // Sort by score descending, take topK
    allResults.sort((a, b) => b.score - a.score);
    const top = allResults.slice(0, topK);

    console.log(
      `[Qdrant]         Searched ${this.collections.length} collections → ${allResults.length} total hits, returning ${top.length}`,
    );

    return top;
  }

  /** Health check — verify Qdrant is reachable and collections exist. */
  async health(): Promise<number> {
    const collections = await this.client.getCollections();
    let totalPoints = 0;

    for (const coll of collections.collections) {
      const name = coll.name;
      if (this.collections.includes(name)) {
        try {
          const info = await this.client.getCollection(name);
          totalPoints += (info.points_count ?? 0) as number;
        } catch {
          // Collection not accessible
        }
      }
    }

    console.log(
      `[Qdrant]   Connected — ${totalPoints} total points across ${this.collections.length} collections`,
    );

    return totalPoints;
  }
}
