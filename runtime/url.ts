/** One conservative URI path representation for catalog matching and Cedar facts. */
export function httpPath(url: URL) {
  if (/%(?:2f|5c|25)/i.test(url.pathname))
    throw new Error('Encoded separators and double encoding are unsupported');
  const path = decodeURIComponent(url.pathname);
  let hasControl = false;
  for (let index = 0; index < path.length; index++) {
    const code = path.charCodeAt(index);
    if (code < 32 || code === 127) hasControl = true;
  }
  if (/[\\;]/.test(path) || path.includes('//') || hasControl)
    throw new Error('Ambiguous HTTP path');
  return path;
}
