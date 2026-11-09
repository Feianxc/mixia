import { beforeAll } from 'vitest';
import { initCrypto, randomBytes, signKeysFromSeed, boxKeysFromSeed, kdf } from '../src/crypto';
import { DeviceStore, SoftwareKeys } from '../src/device';
import { MemoryKV } from '../src/store';
import { Vault, type Policy } from '../src/vault';

export const ready = () => beforeAll(() => initCrypto());

/** 测试专用的最低参数，避免每次 Argon2 都跑 128 MiB。 */
export const TEST_MEM = 64 * 1024 * 1024;

export function keys() {
  const seed = randomBytes(32);
  return {
    sign: signKeysFromSeed(kdf(seed, 'sign')),
    box: boxKeysFromSeed(kdf(seed, 'box')),
  };
}

export async function makeVault(policy: Policy = 'cloud', deviceId = 'dev-a') {
  const kv = new MemoryKV();
  const key = randomBytes(32);
  const author = { deviceId, sign: keys().sign };
  const v = await Vault.create(kv, { vaultId: 'vault-1', policy }, key, author, () => 7);
  return { v, kv, key, author };
}

export async function makeDevice(passphrase = 'correct horse') {
  const kv = new MemoryKV();
  const hw = new SoftwareKeys(kv);
  const { store, session } = await DeviceStore.create(kv, hw, passphrase, TEST_MEM);
  return { kv, hw, store, session };
}
