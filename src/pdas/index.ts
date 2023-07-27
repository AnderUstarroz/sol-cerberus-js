import * as anchor from '@project-serum/anchor';
import {PublicKey} from '@solana/web3.js';
import {SOL_CERBERUS_PROGRAM_ID, METADATA_PROGRAM_ID} from '../constants';

export async function appPda(appId: PublicKey) {
  return (
    await PublicKey.findProgramAddressSync(
      [anchor.utils.bytes.utf8.encode('app'), appId.toBuffer()],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function rulePda(
  appId: PublicKey,
  role: string,
  resource: string,
  permission: string,
  namespace: number = 0,
) {
  return (
    await PublicKey.findProgramAddressSync(
      [
        new Uint8Array([namespace]),
        anchor.utils.bytes.utf8.encode(role),
        anchor.utils.bytes.utf8.encode(resource),
        anchor.utils.bytes.utf8.encode(permission),
        appId.toBuffer(),
      ],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

/**
 * Empty address "null" will be considered the wildcard "*" (applied to all users)
 */
export async function rolePda(
  appId: PublicKey,
  role: string,
  address: PublicKey | null | '*',
) {
  return (
    await PublicKey.findProgramAddressSync(
      [
        anchor.utils.bytes.utf8.encode(role),
        !address || address === '*'
          ? anchor.utils.bytes.utf8.encode('*')
          : address.toBuffer(),
        appId.toBuffer(),
      ],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function seedPda(signer: PublicKey) {
  return (
    await PublicKey.findProgramAddressSync(
      [anchor.utils.bytes.utf8.encode('seed'), signer.toBuffer()],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function nftMetadataPda(mint: PublicKey) {
  return (
    await PublicKey.findProgramAddressSync(
      [
        anchor.utils.bytes.utf8.encode('metadata'),
        METADATA_PROGRAM_ID.toBuffer(),
        mint.toBuffer(),
      ],
      METADATA_PROGRAM_ID,
    )
  )[0];
}
