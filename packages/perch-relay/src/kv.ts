/** The key-value subset the relay needs (Cloudflare Workers KV fits it). */
export interface Kv {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  list(options: { prefix: string; cursor?: string }): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }>;
}

/** An in-memory `Kv`, for tests and single-process relays. */
export class MemoryKv implements Kv {
  private readonly data = new Map<string, { value: string; expires?: number }>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  async get(key: string): Promise<string | null> {
    const v = this.data.get(key);
    if (!v) return null;
    if (v.expires !== undefined && v.expires <= this.now()) {
      this.data.delete(key);
      return null;
    }
    return v.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const ttl = options?.expirationTtl;
    this.data.set(key, { value, expires: ttl === undefined ? undefined : this.now() + ttl * 1000 });
  }

  async list(options: { prefix: string }) {
    const keys: { name: string }[] = [];
    for (const name of [...this.data.keys()].sort()) {
      if (name.startsWith(options.prefix) && (await this.get(name)) !== null) keys.push({ name });
    }
    return { keys, list_complete: true };
  }
}
