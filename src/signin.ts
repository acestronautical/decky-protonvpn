const usernameStorageKey = "decky-protonvpn.username";

export function cachedUsername(): string {
  try {
    const username = globalThis.localStorage.getItem(usernameStorageKey) ?? "";
    return /^[A-Za-z0-9._+@-]{1,254}$/.test(username) ? username : "";
  } catch {
    return "";
  }
}

export function rememberUsername(username: string): void {
  if (!/^[A-Za-z0-9._+@-]{1,254}$/.test(username)) return;
  try {
    globalThis.localStorage.setItem(usernameStorageKey, username);
  } catch {
    return;
  }
}

export function encodeSignIn(credentials: {
  username: string;
  password: string;
  totp: string;
}): Uint8Array {
  if (
    !credentials.username ||
    credentials.username.length > 254 ||
    /[^A-Za-z0-9._+@-]/.test(credentials.username) ||
    !credentials.password ||
    /[\0\r\n]/.test(credentials.password) ||
    /[\0\r\n]/.test(credentials.totp)
  ) {
    throw new Error("Enter a valid Proton username and password");
  }
  const plaintext = new TextEncoder().encode(JSON.stringify(credentials));
  if (plaintext.byteLength > 446) {
    plaintext.fill(0);
    throw new Error("These credentials exceed the secure form's size limit; use Desktop Mode sign-in");
  }
  return plaintext;
}

export async function encryptSignIn(
  publicKeyPem: string,
  plaintext: Uint8Array,
): Promise<string> {
  try {
    if (!globalThis.crypto?.subtle) {
      throw new Error("Secure sign-in is unavailable here; use Desktop Mode sign-in");
    }
    const encodedKey = publicKeyPem.replace(
      /-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g,
      "",
    );
    const keyBytes = Uint8Array.from(atob(encodedKey), (character) =>
      character.charCodeAt(0),
    );
    const publicKey = await crypto.subtle.importKey(
      "spki",
      keyBytes,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"],
    );
    if (!(plaintext.buffer instanceof ArrayBuffer)) {
      throw new Error("Secure sign-in requires a non-shared buffer");
    }
    const encrypted = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength),
    );
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } finally {
    plaintext.fill(0);
  }
}