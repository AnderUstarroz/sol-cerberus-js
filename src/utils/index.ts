import {PublicKey} from '@solana/web3.js';

export function short_key(publicKey: PublicKey | string) {
  if (typeof publicKey !== 'string') {
    publicKey = publicKey.toBase58();
  }
  return `${publicKey.slice(0, 4)}..${publicKey.slice(-4)}`;
}
