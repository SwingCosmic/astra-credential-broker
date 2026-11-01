import { createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const canonical = (value) => {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw Error("unsafe number");
  return JSON.stringify(value);
};
const b64 = (v) => Buffer.from(v).toString("base64url");
const bytes = (v) => Buffer.from(v, "base64url");
const utf8 = (v) => Buffer.from(canonical(v), "utf8");
const path = fileURLToPath(new URL("../vectors/transfer-v1.json", import.meta.url));

if (process.argv.includes("--generate")) {
  mkdirSync(fileURLToPath(new URL("../vectors/", import.meta.url)), { recursive: true });
  const migration = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const salt = Buffer.from(Array.from({ length: 32 }, (_, i) => 255 - i));
  const nonce = Buffer.from(Array.from({ length: 12 }, (_, i) => i + 10));
  const info = utf8(["astraconductor.credential-transfer.v1", "vector-vault", "vector-version", "vector-attempt", "vector-transfer"]);
  const header = {
    format: "astraconductor.credential-transfer", version: 1, vaultId: "vector-vault",
    storageVersion: "vector-version", attemptId: "vector-attempt", transferId: "vector-transfer", keyId: "vector-key",
    cipher: { name: "AES-256-GCM", nonce: b64(nonce), tagLength: 128 },
    kdf: { name: "HKDF-SHA-256", salt: b64(salt), info: b64(info), outputLength: 32 }, payloadSchemaVersion: 1,
  };
  const snapshot = {
    vaultId: header.vaultId, storageVersion: header.storageVersion, attemptId: header.attemptId, keyId: header.keyId,
    masterKey: b64(Buffer.alloc(32, 0x42)),
    records: [{ description: { credentialId: "opaque-example", revision: "1", createdByClientId: "third-party",
      lastUpdatedByClientId: "third-party", metadata: { "界": "\u2028\u2029😀<>&", supportsInference: "true", supportsUsage: "false" },
      contentType: "application/third-party", payloadFormatVersion: 1 }, payload: b64(Buffer.from([0, 255, 1, 128])) }],
  };
  const key = hkdfSync("sha256", migration, salt, info, 32);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(utf8(header));
  const ciphertext = Buffer.concat([cipher.update(utf8(snapshot)), cipher.final()]);
  const vector = { migrationKey: "acm1_" + b64(migration), snapshot,
    package: { header, ciphertext: b64(ciphertext), tag: b64(cipher.getAuthTag()) } };
  // Keep the checked-in fixture ASCII-only, including Unicode line/paragraph separators
  // and UTF-16 surrogate pairs. Escapes affect presentation, never authenticated bytes.
  const json = JSON.stringify(vector, null, 2).replace(/[\u007f-\uffff]/g,
    (character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));
  writeFileSync(path, json + "\n", "utf8");
}

function verify(file) {
  const vector = JSON.parse(readFileSync(file, "utf8"));
  const { header } = vector.package;
  const info = utf8(["astraconductor.credential-transfer.v1", header.vaultId, header.storageVersion, header.attemptId, header.transferId]);
  assert.equal(header.kdf.info, b64(info));
  const key = hkdfSync("sha256", bytes(vector.migrationKey.slice(5)), bytes(header.kdf.salt), info, 32);
  const decipher = createDecipheriv("aes-256-gcm", key, bytes(header.cipher.nonce));
  decipher.setAAD(utf8(header));
  decipher.setAuthTag(bytes(vector.package.tag));
  const plain = Buffer.concat([decipher.update(bytes(vector.package.ciphertext)), decipher.final()]);
  assert.equal(plain.toString("utf8"), canonical(vector.snapshot));
  console.log("PASS JavaScript HKDF/AES-GCM/JCS interoperability: " + file);
}
verify(path);
const dotnetIndex = process.argv.indexOf("--dotnet");
if (dotnetIndex >= 0) verify(process.argv[dotnetIndex + 1]);
