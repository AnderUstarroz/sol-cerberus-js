import {PublicKey} from '@solana/web3.js';
import {BN} from '@project-serum/anchor';

export function short_key(publicKey: PublicKey | string) {
  if (typeof publicKey !== 'string') {
    publicKey = publicKey.toBase58();
  }
  return `${publicKey.slice(0, 4)}..${publicKey.slice(-4)}`;
}

export const rustToDate = (value: BN | null) =>
  value ? new Date((value as BN).toNumber() * 1000) : null;

export const dateToRust = (value: Date | null) =>
  value ? new BN(Math.floor(value.getTime() / 1000)) : null;
