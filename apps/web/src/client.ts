import type { DatasetResponse } from '../../../packages/contracts/generated/api';

export type Connection = { token: string; dataset: DatasetResponse | null; sessionId?: string };

export class ApiError extends Error {
  constructor(
    message: string, public readonly status: number, public readonly code?: string,
    public readonly details?: Record<string, unknown>,
  ) { super(`${message} (${status})`); }
}

export async function api<T>(connection: Connection, path: string, signal: AbortSignal, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { ...init, signal,
    headers: { ...init.headers, Authorization: `Bearer ${connection.token}` } });
  const data = await response.json();
  if (!response.ok) throw new ApiError(
    data.error?.message ?? '请求失败', response.status, data.error?.code, data.error?.details,
  );
  return data as T;
}
