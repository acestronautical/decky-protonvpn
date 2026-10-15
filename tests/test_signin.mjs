import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

globalThis.crypto ??= webcrypto;
const source = readFileSync(new URL("../src/signin.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
}).outputText;
const { encodeSignIn, encryptSignIn } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

const bridge = `
import base64, json, os, sys, tempfile, types
from unittest.mock import patch
sys.modules.setdefault("decky", types.ModuleType("decky"))
import main
request = json.load(sys.stdin)
if request["action"] == "keypair":
    private, public = main._generate_signin_keypair()
    print(json.dumps({"private": base64.b64encode(private).decode(), "public": public}))
else:
    private = bytearray(base64.b64decode(request["private"]))
    main.SIGNIN_SESSIONS["test"] = (private, float("inf"))
    original_temporary_file = tempfile.TemporaryFile
    def test_key_file(**options):
        if not os.path.isdir("/dev/shm"):
            options["dir"] = tempfile.gettempdir()
        return original_temporary_file(**options)
    with patch.object(main.tempfile, "TemporaryFile", test_key_file), patch.object(
        main, "_run_cli_signin", side_effect=lambda credentials: {"matches": credentials == request["expected"]}
    ) as signin:
        try:
            result = main._complete_signin("test", request["ciphertext"])
        except ValueError:
            result = {"rejected": True}
        try:
            main._complete_signin("test", request["ciphertext"])
        except ValueError:
            result["replay_rejected"] = True
        result["calls"] = signin.call_count
        result["wiped"] = not any(private)
        result["remaining"] = len(main.SIGNIN_SESSIONS)
        print(json.dumps(result))
`;

function backend(request) {
  return JSON.parse(execFileSync("python3", ["-c", bridge], {
    cwd: new URL("..", import.meta.url),
    input: JSON.stringify(request),
    encoding: "utf8",
    timeout: 60000,
  }));
}

const keypair = backend({ action: "keypair" });
const credentials = { username: "dummy-user", password: "dummy-password", totp: "123456" };

test("Web Crypto encrypts credentials that backend OpenSSL decrypts once", async () => {
  const plaintext = encodeSignIn(credentials);
  const ciphertext = await encryptSignIn(keypair.public, plaintext);
  assert.equal(ciphertext.length, 684);
  assert.ok(plaintext.every((value) => value === 0));
  assert.deepEqual(backend({ action: "decrypt", private: keypair.private, ciphertext, expected: credentials }), {
    matches: true, replay_rejected: true, calls: 1, wiped: true, remaining: 0,
  });
});

test("modified ciphertext is rejected before CLI execution and key is wiped", async () => {
  const ciphertext = await encryptSignIn(keypair.public, encodeSignIn(credentials));
  const modified = Buffer.from(ciphertext, "base64");
  modified[0] ^= 1;
  assert.deepEqual(backend({
    action: "decrypt", private: keypair.private,
    ciphertext: modified.toString("base64"), expected: credentials,
  }), { rejected: true, replay_rejected: true, calls: 0, wiped: true, remaining: 0 });
});

test("maximum RSA-OAEP payload fits without truncation", async () => {
  const empty = { ...credentials, password: "" };
  const overhead = new TextEncoder().encode(JSON.stringify(empty)).length;
  const maximum = { ...credentials, password: "x".repeat(446 - overhead) };
  const plaintext = encodeSignIn(maximum);
  assert.equal(plaintext.length, 446);
  const ciphertext = await encryptSignIn(keypair.public, plaintext);
  assert.equal(backend({ action: "decrypt", private: keypair.private, ciphertext, expected: maximum }).matches, true);
  assert.throws(() => encodeSignIn({ ...maximum, password: maximum.password + "x" }), /size limit/);
});

test("size validation counts UTF-8 bytes and JSON escapes", () => {
  for (const password of ["\u00e9".repeat(250), '"'.repeat(250)]) {
    assert.throws(() => encodeSignIn({ ...credentials, password }), /size limit/);
  }
});

test("invalid key still clears the plaintext buffer", async () => {
  const plaintext = encodeSignIn(credentials);
  await assert.rejects(encryptSignIn("invalid", plaintext));
  assert.ok(plaintext.every((value) => value === 0));
});

test("form rejects line injection and empty credentials", () => {
  for (const invalid of [
    { username: "bad user" }, { username: "user\n" },
    { password: "" }, { password: "bad\ninput" },
    { password: "bad\0input" }, { totp: "bad\rinput" },
  ]) {
    assert.throws(() => encodeSignIn({ ...credentials, ...invalid }), /valid Proton/);
  }
});