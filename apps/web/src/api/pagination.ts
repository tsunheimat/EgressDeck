/** Collection reads have a byte bound in addition to their row/page bounds. */
export async function boundedListJSON(response: Response, signal?: AbortSignal): Promise<unknown> {
  const maxBytes = 4 * 1024 * 1024
  const length = response.headers.get('Content-Length')
  if (length && Number(length) > maxBytes) {
    await response.body?.cancel()
    throw new Error('The collection page exceeds the 4 MiB browser response limit.')
  }
  if (!response.body) throw new Error('The controller returned an empty collection response.')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let bytes = 0
  let text = ''
  const abort = () => { void reader.cancel() }
  signal?.addEventListener('abort', abort, { once: true })
  try {
    while (true) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      const chunk = await reader.read()
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      if (chunk.done) break
      bytes += chunk.value.byteLength
      if (bytes > maxBytes) {
        await reader.cancel()
        throw new Error('The collection page exceeds the 4 MiB browser response limit.')
      }
      text += decoder.decode(chunk.value, { stream: true })
    }
    return JSON.parse(text + decoder.decode()) as unknown
  } finally {
    signal?.removeEventListener('abort', abort)
    reader.releaseLock()
  }
}
