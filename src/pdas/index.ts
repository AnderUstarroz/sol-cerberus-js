import * as anchor from '@project-serum/anchor';
import {PublicKey} from '@solana/web3.js';
import {SOL_CERBERUS_PROGRAM_ID, METADATA_PROGRAM_ID} from '../constants';

export async function sc_app_pda(appId: PublicKey) {
  return (
    await PublicKey.findProgramAddressSync(
      [anchor.utils.bytes.utf8.encode('app'), appId.toBuffer()],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function sc_rule_pda(
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
 * Empty address is considered the wildcard "*" (applied to all users)
 */
export async function sc_role_pda(
  appId: PublicKey,
  role: string,
  address: PublicKey | null,
) {
  return (
    await PublicKey.findProgramAddressSync(
      [
        anchor.utils.bytes.utf8.encode(role),
        address ? address.toBuffer() : anchor.utils.bytes.utf8.encode('*'),
        appId.toBuffer(),
      ],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function sc_seed_pda(signer: PublicKey) {
  return (
    await PublicKey.findProgramAddressSync(
      [anchor.utils.bytes.utf8.encode('seed'), signer.toBuffer()],
      SOL_CERBERUS_PROGRAM_ID,
    )
  )[0];
}

export async function nft_metadata_pda(mint: PublicKey) {
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
