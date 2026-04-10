type GenericRecord = Record<string, unknown>

export function asRecord(value: unknown): GenericRecord {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as GenericRecord
  }

  return {}
}

export function extractList(value: unknown, keys: string[] = []): GenericRecord[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is GenericRecord => Boolean(item) && typeof item === 'object')
  }

  const record = asRecord(value)

  for (const key of keys) {
    const candidate = record[key]
    if (Array.isArray(candidate)) {
      return candidate.filter((item): item is GenericRecord => Boolean(item) && typeof item === 'object')
    }
  }

  const fallbackKeys = ['items', 'data', 'results']
  for (const key of fallbackKeys) {
    const candidate = record[key]
    if (Array.isArray(candidate)) {
      return candidate.filter((item): item is GenericRecord => Boolean(item) && typeof item === 'object')
    }
  }

  return []
}

export function extractNumber(value: unknown, keys: string[], fallback = 0): number {
  const record = asRecord(value)

  for (const key of keys) {
    const candidate = record[key]

    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
      return candidate
    }

    if (typeof candidate === 'string') {
      const parsed = Number(candidate)
      if (Number.isFinite(parsed)) {
        return parsed
      }
    }
  }

  return fallback
}

export function extractText(value: unknown, keys: string[], fallback = ''): string {
  const record = asRecord(value)

  for (const key of keys) {
    const candidate = record[key]
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate
    }
  }

  return fallback
}

export function extractSeries(
  value: unknown,
  keys: string[]
): {
  labels: string[]
  values: number[]
} {
  const source = asRecord(value)

  for (const key of keys) {
    const candidate = source[key]
    if (!Array.isArray(candidate)) {
      continue
    }

    const labels: string[] = []
    const values: number[] = []

    for (const item of candidate) {
      const row = asRecord(item)
      const label = extractText(row, ['label', 'name', 'category', 'type', 'time', 'timestamp'])
      const amount = extractNumber(row, ['value', 'count', 'total', 'amount', 'latency'])

      if (label && Number.isFinite(amount)) {
        labels.push(label)
        values.push(amount)
      }
    }

    if (labels.length > 0 && values.length > 0) {
      return { labels, values }
    }
  }

  return { labels: [], values: [] }
}
