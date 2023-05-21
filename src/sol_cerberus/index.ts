import {web3} from '@project-serum/anchor';
import {PublicKey} from '@solana/web3.js';
import * as anchor from '@project-serum/anchor';
import {sc_app_pda, sc_rule_pda, sc_role_pda, nft_metadata_pda} from '../pdas';
import {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';
import {SOL_CERBERUS_PROGRAM_ID} from '../constants';
import SolCerberusIDL from '../idl/sol_cerberus.json';
import {getAssociatedTokenAddress} from '@solana/spl-token';
import {BN} from '@project-serum/anchor';
import {getDB, RULE_STORE, bulk_insert, get_all_rules} from '../db';
import {IDBPDatabase} from 'idb';

// @TODO Remove this hack, only used to get the BN type included on package (used by app.updated_at).
export const BIG_NUMBER: BN = 0;

export type {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';

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

export type AddressTypeType = 'wallet' | 'nft' | 'collection';
export type AddressRustType = {[k: string]: {}};
export interface ResourcesType {
  [resource: string]: PermsType;
}

export interface RolesType {
  [role: string]: ResourcesType;
}

export interface CachedPermsType {
  [namespace: number]: RolesType;
}

export interface AssignedRoleObjectType {
  addressType: AddressTypeType;
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

export interface AddressFilterType {
  [address: string]: PublicKey | null;
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
export interface ConfigType {
  appChangedCallback?: Function;
  rulesChangedCallback?: Function;
  rolesChangedCallback?: Function;
}
export const new_sc_app = (): PublicKey => web3.Keypair.generate().publicKey;

export const addressType: any = {
  Wallet: {wallet: {}},
  NFT: {nft: {}},
  Collection: {collection: {}},
};

export class SolCerberus {
  /** @internal */ #program: anchor.Program<SolCerberusTypes>;
  /** @internal */ #appId: PublicKey;
  /** @internal */ #appPda: PublicKey | null = null;
  /** @internal */ #appData:
    | anchor.IdlAccounts<SolCerberusTypes>['app']
    | null = null;
  /** @internal */ #db: IDBPDatabase | null = null;
  /** @internal */ #permissions: CachedPermsType = {};
  /** @internal */ #wallet: PublicKey;
  /** @internal */ #appListener: number | null = null;
  /** @internal */ #rulesListener: number | null = null;
  /** @internal */ #rolesListener: number | null = null;

  /**
   * Creates Sol Cerberus client
   *
   * @param #appId The Public key of the Sol Cerberus APP ID
   * @param #provider Connection provider
   */
  constructor(
    appId: PublicKey,
    provider: anchor.Provider,
    config: ConfigType = {},
  ) {
    this.#appId = appId;
    this.#program = new anchor.Program(
      SolCerberusIDL as any,
      SOL_CERBERUS_PROGRAM_ID,
      provider,
    );
    this.#wallet = provider.publicKey as PublicKey;
    this.#appListener = this.listenAppEvents(config);
    this.#rulesListener = this.listenRulesEvents(config);
    this.#rolesListener = this.listenRolesEvents(config);
    this.fetchAppData();
  }

  /**
   * Subscribes to Sol Cerberus App updates to refresh the app data
   * whenever the APP has been updated.
   */
  listenAppEvents(config: ConfigType) {
    return this.#program.addEventListener('AppChanged', async (event, slot) => {
      if (event.appId.toBase58() === this.appId.toBase58()) {
        this.fetchAppData(); // Refresh APP data
        if (config.hasOwnProperty('appChangedCallback')) {
          //@ts-ignore
          config.appChangedCallback(event, slot);
        }
      }
    });
  }

  /**
   * Subscribes to Sol Cerberus Rules updates to refresh permissions
   */
  listenRulesEvents(config: ConfigType) {
    return config.rulesChangedCallback
      ? this.#program.addEventListener('RulesChanged', async (event, slot) => {
          if (event.appId.toBase58() === this.appId.toBase58()) {
            //@ts-ignore
            config.rulesChangedCallback(event, slot);
          }
        })
      : null;
  }

  /**
   * Subscribes to Sol Cerberus Role assignation updates (only when a callback is defined)
   */
  listenRolesEvents(config: ConfigType) {
    return config.rolesChangedCallback
      ? this.#program.addEventListener('RolesChanged', async (event, slot) => {
          if (event.appId.toBase58() === this.appId.toBase58()) {
            //@ts-ignore
            config.rolesChangedCallback(event, slot);
          }
        })
      : null;
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
      this.#db = await getDB(this.appId.toBase58(), this.#appData.updatedAt);
    } catch (e) {
      console.error('Failed to fetch APP data', e);
    }
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

  get db() {
    return this.#db;
  }

  set wallet(address: PublicKey) {
    this.#wallet = address;
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

  /**
   * Returns True if the rule is positive for at least one of the provided roles.
   */
  hasPerm(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ) {
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
      let perm = this.#permissions[namespace][role][resource][permission];
      if (!perm.expiresAt || perm.expiresAt > new Date().getTime()) {
        return true;
      }
    } catch (e) {}
    return false;
  }

  /**
   * Returns the first valid (not expired) assigned address
   */
  validAssignedAddress(addresses: AssignedAddressType): string | null {
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

  /**
   * Finds the first Rule definition matching the provided Role, Resource, Permission and namespace.
   */
  findRule(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): [string, string, string, number] | null {
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

  parseAddressType(addressType: AddressRustType): AddressTypeType {
    return Object.keys(addressType)[0] as AddressTypeType;
  }

  /**
   * Fetches the roles assigned to the provided addresses
   */
  async assignedRoles(
    addresses: PublicKey[],
    collectionsMints: AddressFilterType | null = null,
  ): Promise<AddressByRoleType> {
    return (await this.filterAssignedRoles(addresses)).reduce(
      (output, x: RolesByAddressType) => {
        Object.entries(x).map(([address, roles]) => {
          Object.entries(roles).map(([role, values]) => {
            if (!output[role]) {
              output[role] = {};
            }
            output[role][address] = values;
            if (values.addressType === 'collection') {
              if (!collectionsMints || !collectionsMints[address]) {
                throw new Error(
                  `Collection ${address} requires his corresponding Mint address`,
                );
              }
              output[role][address].nftMint = collectionsMints[address];
            }
          });
        });
        return output;
      },
      {},
    );
  }

  /**
   * Fetches the roles assigned to the provided addresses
   * @param accountsFilters Program accounts filters: https://solanacookbook.com/guides/get-program-accounts.html#deep-dive
   */
  async filterAssignedRoles(
    accountsFilters: PublicKey[],
  ): Promise<RolesByAddressType[]> {
    return (
      await Promise.allSettled(
        accountsFilters.map((address: PublicKey) =>
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

  /**
   * Fetches all assigned roles for the current program
   *
   * @param accountsFilters Program accounts filters: https://solanacookbook.com/guides/get-program-accounts.html#deep-dive
   *
   */
  async fetchAssignedRoles(accountsFilters = []): Promise<RolesByAddressType> {
    return (
      await this.#program.account.role.all([
        {
          memcmp: {
            offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
            bytes: this.#appId.toBase58(), // base58 encoded string
          },
        },
        ...accountsFilters,
      ])
    ).reduce((assignedRoles, data) => {
      let address = data.account.address.toBase58();
      if (!assignedRoles.hasOwnProperty(address)) {
        assignedRoles[address] = {};
      }
      assignedRoles[address][data.account.role] = {
        addressType: this.parseAddressType(data.account.addressType),
        createdAt: data.account.createdAt.toNumber() * 1000,
        nftMint: null,
        expiresAt: data.account.expiresAt
          ? data.account.expiresAt.toNumber() * 1000 // Convert to milliseconds
          : null,
      };
      return assignedRoles;
    }, {} as RolesByAddressType);
  }

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
  async accounts(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Default,
  ): Promise<AccountsType> {
    let defaultOutput = {
      solCerberusApp: await this.getAppPda(),
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

  /**
   * Fetches PDA accounts in parallel
   */
  async fetchPdaAccounts(
    roles: AddressByRoleType,
    role: string,
    resource: string,
    permission: string,
    namespace: number,
    assignedAddress: string,
    defaultOutput: AccountsType,
  ): Promise<AccountsType> {
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

  /**
   * Adds NFT fetcher (only needed when using NFT authentication)
   */
  async getTokenAccount(
    assignedRole: AssignedRoleObjectType,
    assignedAddress: string,
  ) {
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

  /**
   * Adds NFT fetcher (only needed when using NFT authentication)
   */
  async getMetadataAccount(assignedRole: AssignedRoleObjectType) {
    if (assignedRole.addressType === 'collection') {
      return nft_metadata_pda(assignedRole.nftMint as PublicKey);
    }
    return null;
  }

  /*
   * Fetches Permissions from blockchain
   */
  async fetchPerms(fromCache: boolean = true) {
    const appData = await this.getAppData();
    let cached = appData?.cached ? await this.cachedPerms() : {};
    // Fetch perms only if they have been modified
    if (!fromCache || !Object.keys(cached).length) {
      let fetched = await this.#program.account.rule.all([
        {
          memcmp: {
            offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
            bytes: this.#appId.toBase58(), // base58 encoded string
          },
        },
      ]);
      cached = this.parsePerms(fetched);
      if (appData?.cached) {
        this.setCachePerms(fetched);
      }
    }
    this.#permissions = cached;
    return cached;
  }

  /**
   * Parse Permissions into following mapped format:
   *
   * {
   *    0: {
   *      role1:  {
   *        resource1: {
   *          permission1: {
   *            createdAt: 1677485630000;
   *            expiresAt: null;
   *          },
   *          resource2: {...}
   *        },
   *      },
   *      role2:  {...}
   *    },
   *    1: {...}
   * }
   */
  parsePerms(fetchedPerms: any): CachedPermsType {
    return fetchedPerms
      ? fetchedPerms.reduce((perms: CachedPermsType, account: any) => {
          const {namespace, role, resource, permission, createdAt, expiresAt} =
            account.account;
          return this.addPerm(
            perms,
            namespace,
            role,
            resource,
            permission,
            createdAt.toNumber() * 1000, // Convert to milliseconds
            expiresAt ? expiresAt.toNumber() * 1000 : null, // Convert to milliseconds
          );
        }, {})
      : {};
  }

  /**
   * Add a new Permission into the cached perms
   */
  addPerm(
    perms: CachedPermsType,
    namespace: number,
    role: string,
    resource: string,
    permission: string,
    createdAt: number,
    expiresAt: number | null,
  ): CachedPermsType {
    if (!perms.hasOwnProperty(namespace)) {
      perms[namespace] = {};
    }
    if (!perms[namespace].hasOwnProperty(role)) {
      perms[namespace][role] = {};
    }
    if (!perms[namespace][role].hasOwnProperty(resource)) {
      perms[namespace][role][resource] = {};
    }
    perms[namespace][role][resource][permission] = {
      createdAt: createdAt,
      expiresAt: expiresAt,
    };
    return perms;
  }

  /**
   * Stores Perms in IDB (When available)
   */
  async setCachePerms(fetchedPerms: any) {
    if (typeof window !== 'undefined' && this.db) {
      // @TODO check the format returned by IDB
      console.debug('Fetched perms:', fetchedPerms);
      debugger;
      bulk_insert(this.db, RULE_STORE, fetchedPerms);
    }
  }

  /**
   * Retrieves Perms from IDB (When available)
   */
  async cachedPerms(): Promise<CachedPermsType> {
    if (typeof window !== 'undefined') {
      if (!this.permissions && this.db) {
        // @TODO check the format returned by IDB
        const rules = await get_all_rules(this.db);
        // @TODO check the format returned by IDB
        console.debug('IDB Rules:', rules);
      }
    }
    return {};
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

  /**
   * Cleanup resources;
   */
  destroy() {
    if (this.#rulesListener !== null) {
      this.program.removeEventListener(this.#rulesListener);
    }
    if (this.#rolesListener !== null) {
      this.program.removeEventListener(this.#rolesListener);
    }
    if (this.#appListener !== null) {
      this.program.removeEventListener(this.#appListener);
    }
  }
}
