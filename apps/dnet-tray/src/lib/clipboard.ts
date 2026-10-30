/** Put `text` on the clipboard. False where the window is not allowed to, so the caller can say what to do instead. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
