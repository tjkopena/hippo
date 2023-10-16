export function str2ab(str: string) : ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export function ab2str(buf : ArrayBuffer) : string {
  return String.fromCharCode(... new Uint8Array(buf));
}
