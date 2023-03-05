import {web3} from '@project-serum/anchor';
import {PublicKey} from '@solana/web3.js';
import * as anchor from '@project-serum/anchor';
import {sc_app_pda, sc_rule_pda, sc_role_pda, nft_metadata_pda} from '../pdas';
import {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';
import {SOL_CERBERUS_PROGRAM_ID} from '../constants';
import SolCerberusIDL from '../idl/sol_cerberus.json';
import {getAssociatedTokenAddress} from '@solana/spl-token';

export enum namespaces {
  Default = 0,
  Internal = 1,
}
export interface PermsType {
  [perm: string]: {
    createdAt: number;
    expiresAt: number | null;
  };
}

export type AddressType = 'wallet' | 'nft' | 'collection';
export type AddressRustType = {[k: string]: {}};
export interface ResourcesType {
  [resource: string]: PermsType;
}

export interface RolesType {
  [role: string]: ResourcesType;
}

export interface NamespacesType {
  [namespace: number]: RolesType;
}

export interface CachedPermsType {
  cachedAt: number;
  latestCreatedAt: number;
  size: number;
  perms: NamespacesType;
}

export interface AssignedRoleObjectType {
  addressType: AddressType;
  createdAt: number;
  nftMint: PublicKey | null;
  expiresAt: number | null;
}
export interface AssignedRolesType {
  [role: string]: AssignedRoleObjectType;
}

export interface RolesByAddressType {
  [address: string]: AssignedRolesType;
}

export interface AssignedAddressType {
  [address: string]: AssignedRoleObjectType;
}

export interface AddressByRoleType {
  [role: string]: AssignedAddressType;
}

export interface AccountsType {
  solCerberusApp: PublicKey;
  solCerberusRule: PublicKey | null;
  solCerberusRole: PublicKey | null;
  solCerberusTokenAcc: PublicKey | null;
  solCerberusMetadata: PublicKey | null;
  solCerberus: PublicKey;
}

export const new_sc_app = (): PublicKey => web3.Keypair.generate().publicKey;

export const DEFAULT_CACHED_PERMS: CachedPermsType = {
  cachedAt: 0,
  latestCreatedAt: 0,
  size: 0,
  perms: {},
};

export class SolCerberusClient {
  /** @internal */ #program: anchor.Program<SolCerberusTypes>;
  /** @internal */ #appId: PublicKey;
  /** @internal */ #appPda: PublicKey | null = null;
  /** @internal */ #appData:
    | anchor.IdlAccounts<SolCerberusTypes>['app']
    | null = null;
  /** @internal */ #permissions: CachedPermsType = DEFAULT_CACHED_PERMS;
  /** @internal */ #wallet: PublicKey;

  /**
   * Creates Sol Cerberus client
   *
   * @param #_program The Public key of the Sol Cerberus APP
   * @param #_appId Anchor program
   */
  constructor(appId: PublicKey, provider: anchor.Provider) {
    this.#appId = appId;
    this.#program = new anchor.Program(
      SolCerberusIDL as any,
      SOL_CERBERUS_PROGRAM_ID,
      provider,
    );
    this.#wallet = provider.publicKey as PublicKey;
    this.fetchAppData();
    this.refreshPerms();
  }

  async fetchAppPda(): Promise<PublicKey> {
    this.#appPda = await sc_app_pda(this.#appId);
    return this.#appPda;
  }
  async fetchAppData() {
    try {
      this.#appData = await this.program.account.app.fetch(
        await this.getAppPda(),
      );
    } catch (e) {}
    return this.#appData;
  }

  get program() {
    return this.#program;
  }

  get appId() {
    return this.#appId;
  }

  get wallet() {
    return this.#wallet;
  }

  async getAppPda(): Promise<PublicKey> {
    return this.#appPda ? this.#appPda : await this.fetchAppPda();
  }

  async getAppData() {
    return this.#appData ? this.#appData : await this.fetchAppData();
  }

  get permissions() {
    return this.#permissions;
  }

  permsWildcards(resource: string, permission: string) {
    return [
      [resource, permission],
      [resource, '*'],
      ['*', permission],
      ['*', '*'],
    ];
  }

  hasPerm(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ) {
    /**
     * Returns True if the rule is positive for at least one of the provided roles.
     */
    // Authority has Full access:
    if (
      this.#appData &&
      this.#appData.authority.toBase58() === this.#wallet.toBase58()
    ) {
      return true;
    }
    return !!this.findRule(roles, resource, permission, namespace);
  }

  hasRule(
    role: string,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): boolean {
    try {
      let perm = this.#permissions.perms[namespace][role][resource][permission];
      if (!perm.expiresAt || perm.expiresAt > new Date().getTime()) {
        return true;
      }
    } catch (e) {}
    return false;
  }

  validAssignedAddress(addresses: AssignedAddressType): string | null {
    /**
     * Returns the first valid assigned address (not expired)
     */
    for (const address in addresses) {
      if (
        !addresses[address].expiresAt ||
        (addresses[address].expiresAt as number) > new Date().getTime()
      ) {
        return address;
      }
    }
    return null;
  }

  findRule(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): [string, string, string, number] | null {
    /**
     * Finds the first Rule definition matching the provided Role, Resource, Permission and namespace.
     */
    for (const role in roles) {
      // Verify assigned role is not expired
      if (this.validAssignedAddress(roles[role])) {
        for (const [res, perm] of this.permsWildcards(resource, permission)) {
          if (this.hasRule(role, res, perm, namespace)) {
            return [role, res, perm, namespace];
          }
        }
      }
    }
    return null;
  }

  async getRulePda(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): Promise<PublicKey | null> {
    try {
      const rule = this.findRule(roles, resource, permission, namespace);
      if (!rule) {
        return null;
      }
      return await sc_rule_pda(this.appId, ...rule);
    } catch (e) {}

    return null;
  }

  parseAddressType(addressType: AddressRustType): AddressType {
    return Object.keys(addressType)[0] as AddressType;
  }

  async assignedRoles(addresses: PublicKey[]): Promise<AddressByRoleType> {
    /**
     * Fetches the roles assigned to the provided addresses
     */
    return (await this.filterAssignedRoles(addresses)).reduce(
      (output, x: RolesByAddressType) => {
        Object.entries(x).map(([address, roles]) => {
          Object.entries(roles).map(([role, values]) => {
            if (!output[role]) {
              output[role] = {};
            }
            output[role][address] = values;
          });
        });
        return output;
      },
      {},
    );
  }

  async filterAssignedRoles(
    addresses: PublicKey[],
  ): Promise<RolesByAddressType[]> {
    /**
     * Fetches the roles assigned to the provided addresses
     */
    return (
      await Promise.allSettled(
        addresses.map((address: PublicKey) =>
          this.fetchAssignedRoles([
            //@ts-ignore
            {
              memcmp: {
                offset: 40, // Starting byte of the Address Pubkey
                bytes: address.toBase58(), // Address as base58 encoded string
              },
            },
          ]),
        ),
      )
    )
      .filter((r: any) => r.status === 'fulfilled')
      .map((r: any) => r.value);
  }

  async fetchAssignedRoles(filters = []): Promise<RolesByAddressType> {
    /**
     * Fetches all assigned roles for the current program
     */
    return (
      await this.#program.account.role.all([
        {
          memcmp: {
            offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
            bytes: this.#appId.toBase58(), // base58 encoded string
          },
        },
        ...filters,
      ])
    ).reduce((assignedRoles, data) => {
      assignedRoles[data.account.address.toBase58()] = {
        [data.account.role]: {
          addressType: this.parseAddressType(data.account.addressType),
          createdAt: data.account.createdAt.toNumber() * 1000,
          nftMint: null,
          expiresAt: data.account.expiresAt
            ? data.account.expiresAt.toNumber() * 1000
            : null,
        },
      };
      return assignedRoles;
    }, {} as RolesByAddressType);
  }

  async accounts(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): Promise<AccountsType> {
    /**
     * Generates the required PDAs to perform the provided transaction:
     *    - solCerberusApp: app PDA,
     *    - solCerberusRule: rule PDA,
     *    - solCerberusRole: role PDA,
     *    - solCerberusTokenAcc: tokenAccount PDA,
     *    - solCerberusMetadata: Metaplex PDA,
     *    - solCerberus: Program PDA,
     *
     */
    let defaultOutput = {
      solCerberusApp: this.#appPda,
      solCerberusRule: null,
      solCerberusRole: null,
      solCerberusTokenAcc: null,
      solCerberusMetadata: null,
      solCerberus: this.program.programId,
    } as AccountsType;
    try {
      const rule = this.findRule(roles, resource, permission, namespace);
      if (!rule) {
        return defaultOutput;
      }
      const [roleFound, resourceFound, PermissionFound, ns] = rule;
      const validAddress = this.validAssignedAddress(roles[roleFound]);
      if (validAddress) {
        return await this.fetchPdaAccounts(
          roles,
          roleFound,
          resourceFound,
          PermissionFound,
          ns,
          validAddress,
          defaultOutput,
        );
      }
    } catch (e) {
      console.error(e);
    }
    return defaultOutput;
  }

  async fetchPdaAccounts(
    roles: AddressByRoleType,
    role: string,
    resource: string,
    permission: string,
    namespace: number,
    assignedAddress: string,
    defaultOutput: AccountsType,
  ): Promise<AccountsType> {
    /**
     * Fetches PDA accounts in parallel
     */
    let asyncFuncs = [];
    // Rule PDA fetcher
    asyncFuncs.push(async () =>
      sc_rule_pda(this.appId, role, resource, permission, namespace),
    );
    // Role PDA fetcher
    asyncFuncs.push(async () =>
      sc_role_pda(this.appId, role, new PublicKey(assignedAddress)),
    );
    // tokenAccount PDA fetcher
    asyncFuncs.push(async () =>
      this.getTokenAccount(roles[role][assignedAddress], assignedAddress),
    );
    // Metadata PDA fetcher (not required)
    asyncFuncs.push(async () =>
      this.getMetadataAccount(roles[role][assignedAddress]),
    );
    const pdaNames = [
      'solCerberusRule',
      'solCerberusRole',
      'solCerberusTokenAcc',
      'solCerberusMetadata',
    ];
    (await Promise.allSettled(asyncFuncs.map(f => f()))).map(
      (pdaRequest: any, index: number) => {
        // @ts-ignore
        defaultOutput[pdaNames[index]] =
          pdaRequest.status === 'fulfilled' ? pdaRequest.value : null;
      },
    );
    return defaultOutput;
  }

  async getTokenAccount(
    assignedRole: AssignedRoleObjectType,
    assignedAddress: string,
  ) {
    /**
     * Adds NFT fetcher (only needed when using NFT authentication)
     */
    if (assignedRole.addressType === 'nft') {
      return getAssociatedTokenAddress(
        new PublicKey(assignedAddress),
        this.wallet,
      );
    } else if (assignedRole.addressType === 'collection') {
      if (!assignedRole.nftMint) {
        throw new Error(
          `Missing NFT Mint address for collection: "${assignedAddress}"`,
        );
      }
      return getAssociatedTokenAddress(assignedRole.nftMint, this.wallet);
    }
    return null;
  }

  async getMetadataAccount(assignedRole: AssignedRoleObjectType) {
    /**
     * Adds NFT fetcher (only needed when using NFT authentication)
     */
    if (assignedRole.addressType === 'collection') {
      return nft_metadata_pda(assignedRole.nftMint as PublicKey);
    }
    return null;
  }

  async refreshPerms() {
    /*
     * Fetches Permissions from blockchain
     */
    let cached = this.cachedPerms();
    let fetched = await this.#program.account.rule.all([
      {
        memcmp: {
          offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
          bytes: this.#appId.toBase58(), // base58 encoded string
        },
      },
    ]);
    let latestCreatedAt: number = fetched.reduce(
      (latestDate: number, data: any) => {
        let date = data.account.createdAt.toNumber() * 1000;
        return latestDate >= date ? latestDate : date;
      },
      0,
    );
    // Update cache only if Perms have been modified (different size or different creation date)
    if (
      cached.latestCreatedAt < latestCreatedAt ||
      cached.size !== fetched.length
    ) {
      cached = this.parsePerms(fetched);
      this.cachePerms(cached);
    }
    this.#permissions = cached;
  }

  parsePerms(fetchedPerms: any): CachedPermsType {
    /**
     * Parse Permissions into following mapped format:
     *
     * {
     *   cachedAt: 0,
     *   latestCreatedAt: 0,
     *   perms: {
     *      0: {
     *       role1:  {
     *          resource1: {
     *            permission1: {
     *              createdAt: 1677485630000;
     *             expiresAt: null;
     *           },
     *           resource2: {...}
     *          },
     *       },
     *        role2:  {...}
     *      },
     *      1: {...}
     *   },
     * }
     *
     */
    if (!fetchedPerms) return DEFAULT_CACHED_PERMS;

    return fetchedPerms.reduce((result: CachedPermsType, account: any) => {
      let data = account.account;
      if (!result.perms.hasOwnProperty(data.namespace)) {
        result.perms[data.namespace] = {};
      }
      if (!result.perms[data.namespace].hasOwnProperty(data.role)) {
        result.perms[data.namespace][data.role] = {};
      }
      if (
        !result.perms[data.namespace][data.role].hasOwnProperty(data.resource)
      ) {
        result.perms[data.namespace][data.role][data.resource] = {};
      }
      let created = data.createdAt.toNumber() * 1000; // Convert to milliseconds
      result.perms[data.namespace][data.role][data.resource][data.permission] =
        {
          createdAt: created,
          expiresAt: data.expiresAt ? data.expiresAt.toNumber() * 1000 : null,
        };
      result.size += 1;
      if (created > result.latestCreatedAt) {
        result.latestCreatedAt = created;
      }
      return result;
    }, DEFAULT_CACHED_PERMS);
  }

  cachePermsKey(): string {
    return `SolCerberus-Perms-${this.#appId.toBase58()}`;
  }

  cachePerms(perms: CachedPermsType) {
    /**
     * Stores Perms in localStorage
     */
    perms.cachedAt = new Date().getTime();
    localStorage.setItem(this.cachePermsKey(), JSON.stringify(perms));
  }

  cachedPerms(): CachedPermsType {
    /**
     * Retrieves Perms from localStorage
     */
    let cached = JSON.parse(
      localStorage.getItem(this.cachePermsKey()) as string,
    );
    return cached ? cached : DEFAULT_CACHED_PERMS;
  }

  isUnauthorizedError(e: any) {
    return this.isAnchorError(e) && e.error.errorCode.code === 'Unauthorized'
      ? true
      : false;
  }

  isAnchorError(e: any) {
    return (
      e.hasOwnProperty('error') &&
      e.error.hasOwnProperty('errorCode') &&
      e.error.hasOwnProperty('errorMessage') &&
      e.error.errorCode.hasOwnProperty('code')
    );
  }
}
