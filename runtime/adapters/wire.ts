// DataView keeps the protocol parser independent of conflicting browser/Node
// Buffer ambient types in the shared web + CLI TypeScript project.
const view = (bytes: Uint8Array) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
export const u16be = (bytes: Uint8Array, offset = 0) =>
  view(bytes).getUint16(offset, false);
export const u16le = (bytes: Uint8Array, offset = 0) =>
  view(bytes).getUint16(offset, true);
export const u32be = (bytes: Uint8Array, offset = 0) =>
  view(bytes).getUint32(offset, false);
export const u32le = (bytes: Uint8Array, offset = 0) =>
  view(bytes).getUint32(offset, true);
export const uintle = (bytes: Uint8Array, offset: number, length: number) => {
  if (length < 1 || length > 4 || offset + length > bytes.length)
    throw new Error('Invalid wire integer');
  let value = 0;
  for (let i = 0; i < length; i++) value += bytes[offset + i] * 2 ** (i * 8);
  return value;
};
