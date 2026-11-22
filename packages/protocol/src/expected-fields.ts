import { z } from "zod";

const RecordSchema = z.record(z.string(), z.unknown());

export function matchesExpected(actual: unknown, expected: unknown): boolean {
  const record = RecordSchema.safeParse(expected);
  if (!record.success) return Object.is(actual, expected);
  // Backstop: an empty expected object must not bypass a caller's context checks.
  if (Object.keys(record.data).length === 0) return false;
  const value = RecordSchema.safeParse(actual);
  if (!value.success) return false;
  return Object.entries(record.data).every(([key, field]) => Object.hasOwn(value.data, key) && matchesExpected(value.data[key], field));
}
