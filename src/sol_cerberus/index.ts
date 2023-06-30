import {web3} from '@project-serum/anchor';
import {PublicKey} from '@solana/web3.js';
import * as anchor from '@project-serum/anchor';
import {
  sc_app_pda,
  sc_rule_pda,
  sc_role_pda,
  nft_metadata_pda,
  sc_seed_pda,
} from '../pdas';
import {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';
import {SOL_CERBERUS_PROGRAM_ID} from '../constants';
import SolCerberusIDL from '../idl/sol_cerberus.json';
import {getAssociatedTokenAddress} from '@solana/spl-token';
import {BN} from '@project-serum/anchor';
import {
  getRoleDB,
  getRuleDB,
  RULE_STORE,
  bulk_insert,
  get_all_rules,
  ROLE_STORE,
  fetchAll,
} from '../db';
import {IDBPDatabase} from 'idb';

// @TODO Remove this hack, only used to get the BN type included on package (used by app.updated_at).
export const BIG_NUMBER: BN = 0;

export type {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';

export enum namespaces {
  Rule = 0,
  AssignRole = 1,
  DeleteAssignRole = 2,
  AddRuleNSRole = 3,
  AddRuleResourcePerm = 4,
  DeleteRuleNSRole = 5,
  DeleteRuleResourcePerm = 6,
}

export enum cacheUpdated {
  Roles = 0,
  Rules = 1,
}
export interface PermsType {
  [perm: string]: {
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
  nftMint: PublicKey | null;
  expiresAt: number | null;
}
export interface AssignedRolesType {
  [role: string]: AssignedRoleObjectType;
}

export interface RolesByAddressType {
  [address: string]: AssignedRolesType;
}

export interface CollectionMintAddressType {
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
  solCerberusRule2?: PublicKey | null;
  solCerberusRole: PublicKey | null;
  solCerberusToken: PublicKey | null;
  solCerberusMetadata: PublicKey | null;
  solCerberusSeed: PublicKey | null;
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
  /** @internal */ #roleDB: IDBPDatabase | null = null;
  /** @internal */ #ruleDB: IDBPDatabase | null = null;
  /** @internal */ #permissions: CachedPermsType | null = null;
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
      this.#roleDB = await getRoleDB(
        this.appId.toBase58(),
        this.#appData.rolesUpdatedAt.toNumber(),
      );
      this.#ruleDB = await getRuleDB(
        this.appId.toBase58(),
        this.#appData.rulesUpdatedAt.toNumber(),
      );
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

  get roleDB() {
    return this.#roleDB;
  }

  get ruleDB() {
    return this.#ruleDB;
  }

  get appPda() {
    return this.#appPda;
  }

  get appData() {
    return this.#appData;
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

  isAuthority = () =>
    this.wallet.toBase58() === this.appData?.authority.toBase58();

  get permissions() {
    return this.#permissions;
  }

  async getPermissions() {
    return this.#permissions !== null ? this.#permissions : this.fetchPerms();
  }

  permsWildcards = (resource: string, permission: string) => [
    [resource, permission],
    [resource, '*'],
    ['*', permission],
    ['*', '*'],
  ];

  /**
   * Returns True if the rule is allowed for at least one of the provided roles.
   */
  hasPerm(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Rule,
  ) {
    return this.appData &&
      this.appData.authority.toBase58() === this.wallet.toBase58()
      ? true // Authority always has full access
      : !!this.findRule(roles, resource, permission, namespace);
  }

  hasRule(
    role: string,
    resource: string,
    permission: string,
    namespace: number = namespaces.Rule,
  ): boolean {
    try {
      //@ts-ignore
      let perm = this.permissions[namespace][role][resource][permission];
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
    namespace: number = namespaces.Rule,
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
    namespace: number = namespaces.Rule,
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
    collectionsMints: CollectionMintAddressType | null = null,
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
   * @param useCache boolean
   *
   */
  async fetchAssignedRoles(
    accountsFilters = [],
    useCache: boolean = true,
  ): Promise<RolesByAddressType> {
    const appData = await this.getAppData();
    let cached = appData?.cached ? await this.cachedRoles() : null;
    console.log('CACHED ROLES:', cached);
    if (!useCache || !cached) {
      let fetched = await this.#program.account.role.all([
        {
          memcmp: {
            offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
            bytes: this.#appId.toBase58(), // base58 encoded string
          },
        },
        ...accountsFilters,
      ]);
      cached = this.parseRoles(fetched);
      if (appData?.cached) {
        this.setCachedRoles(fetched);
      }
    }
    return cached;
  }

  /**
   * Parse Roles into following mapped format:
   *
   * {
   *    Ak94...2Uat: {
   *      role1:  {
   *        addressType: "nft"
   *        nftMint: null
   *        expiresAt: 103990020
   *      },
   *      role2:  {...}
   *    },
   *    ekB12...tR38: {...}
   * }
   */
  parseRoles(
    fetchedRoles: anchor.ProgramAccount<
      anchor.IdlAccounts<SolCerberusTypes>['role']
    >[],
  ): RolesByAddressType {
    return fetchedRoles
      ? fetchedRoles.reduce((assignedRoles, data) => {
          let address = data.account.address
            ? data.account.address.toBase58()
            : '*';
          if (!assignedRoles.hasOwnProperty(address)) {
            assignedRoles[address] = {};
          }
          assignedRoles[address][data.account.role] = {
            addressType: this.parseAddressType(data.account.addressType),
            nftMint: null,
            expiresAt: data.account.expiresAt
              ? data.account.expiresAt.toNumber() * 1000 // Convert to milliseconds
              : null,
          };
          return assignedRoles;
        }, {} as RolesByAddressType)
      : {};
    // return fetchedPerms
    //   ? fetchedPerms.reduce((perms: CachedPermsType, account) => {
    //       const {namespace, role, resource, permission, expiresAt} =
    //         account.account;
    //       return this.addPerm(
    //         perms,
    //         namespace,
    //         role,
    //         resource,
    //         permission,
    //         expiresAt ? expiresAt.toNumber() * 1000 : null, // Convert to milliseconds
    //       );
    //     }, {})
    //   : {};
  }

  async defaultAccounts(
    cpi: boolean,
    namespace: namespaces = namespaces.Rule,
  ): Promise<AccountsType> {
    let accs = {
      solCerberusApp: await this.getAppPda(), // Fetched
      solCerberusRole: null,
      solCerberusRule: null,
      solCerberusToken: null,
      solCerberusMetadata: null,
      solCerberusSeed: null,
    } as AccountsType;
    // Cross-Program Invocations (CPI) require Sol Cerberus program account.
    if (cpi) {
      accs.solCerberus = this.program.programId;
    }
    // Add/Delete Rules require an additional "solCerberusRule2" PDA
    if (namespace >= namespaces.AddRuleNSRole) {
      accs.solCerberusRule2 = null;
    }
    return accs;
  }

  /**
   * Generates the required PDAs to perform the provided transaction:
   *    - solCerberusApp: app PDA,
   *    - solCerberusRule: rule PDA,
   *    - solCerberusRole: role PDA,
   *    - solCerberusToken: tokenAccount PDA,
   *    - solCerberusMetadata: Metaplex PDA,
   *    - solCerberusSeed: Seed PDA,
   *    - solCerberus: Program PDA,
   *
   */
  async accounts(
    roles: AddressByRoleType,
    resource: string,
    permission: string,
    namespace: number = namespaces.Rule,
  ): Promise<AccountsType> {
    await this.getPermissions(); // Ensures that APP and perms are fetched.
    let defaultOutput = await this.defaultAccounts(true);
    try {
      const rule = this.findRule(roles, resource, permission, namespace);
      if (!rule || this.isAuthority()) {
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
    // Metadata PDA fetcher (optional)
    asyncFuncs.push(async () =>
      this.getMetadataAccount(roles[role][assignedAddress]),
    );
    // Seed PDA fetcher
    asyncFuncs.push(async () => sc_seed_pda(this.wallet));

    const pdaNames = [
      'solCerberusRule',
      'solCerberusRole',
      'solCerberusToken',
      'solCerberusMetadata',
      'solCerberusSeed',
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
  async fetchPerms(useCache: boolean = true) {
    const appData = await this.getAppData();
    let cached = appData?.cached ? await this.cachedPerms() : null;
    console.log('CACHED RULES:', cached);
    // Fetch perms only if they have been modified
    if (!useCache || !cached) {
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
        this.setCachedPerms(fetched);
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
  parsePerms(
    fetchedPerms: anchor.ProgramAccount<
      anchor.IdlAccounts<SolCerberusTypes>['rule']
    >[],
  ): CachedPermsType {
    return fetchedPerms
      ? fetchedPerms.reduce((perms: CachedPermsType, account) => {
          const {namespace, role, resource, permission, expiresAt} =
            account.account;
          return this.addPerm(
            perms,
            namespace,
            role,
            resource,
            permission,
            expiresAt ? expiresAt.toNumber() * 1000 : null, // Convert to milliseconds
          );
        }, {})
      : {};
  }

  /**
   * Adds new Permission into the cached perms
   */
  addPerm(
    perms: CachedPermsType,
    namespace: number,
    role: string,
    resource: string,
    permission: string,
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
      expiresAt: expiresAt,
    };
    return perms;
  }

  /**
   * Stores Perms on IDB (When available)
   */
  async setCachedPerms(
    fetchedPerms: anchor.ProgramAccount<
      anchor.IdlAccounts<SolCerberusTypes>['rule']
    >[],
  ) {
    if (typeof window !== 'undefined' && this.ruleDB) {
      // @TODO check the format returned by IDB
      console.log('Storing perms:', fetchedPerms);
      bulk_insert(
        this.ruleDB,
        RULE_STORE,
        fetchedPerms.map(item => ({
          namespace: item.account.namespace,
          role: item.account.role,
          resource: item.account.resource,
          permission: item.account.permission,
          expiresAt: item.account.expiresAt
            ? item.account.expiresAt.toNumber() * 1000
            : null,
        })),
      );
    }
  }

  /**
   * Retrieves Perms from IDB (When available)
   */
  async cachedPerms(): Promise<CachedPermsType | null> {
    if (typeof window !== 'undefined') {
      if (this.ruleDB) {
        const rules = await fetchAll(this.ruleDB, RULE_STORE);
        return rules.reduce(
          (perms: CachedPermsType, rule) =>
            this.addPerm(
              perms,
              rule.namespace,
              rule.role,
              rule.resource,
              rule.permission,
              rule.expiresAt, // Already converted to milliseconds
            ),
          {},
        );
      }
    }
    return null;
  }

  /**
   * Stores Roles on IDB (When available)
   */
  async setCachedRoles(
    fetchedRoles: anchor.ProgramAccount<
      anchor.IdlAccounts<SolCerberusTypes>['role']
    >[],
  ) {
    if (typeof window !== 'undefined' && this.roleDB) {
      // @TODO check the format returned by IDB
      console.log('Storing roles:', fetchedRoles);
      bulk_insert(
        this.roleDB,
        ROLE_STORE,
        fetchedRoles.map(item => ({
          address: item.account.address ? item.account.address.toBase58() : '*',
          addressType: this.parseAddressType(item.account.addressType),
          role: item.account.role,
          expiresAt: item.account.expiresAt
            ? item.account.expiresAt.toNumber() * 1000
            : null,
        })),
      );
    }
  }

  /**
   * Retrieves Roles from IDB (When available)
   */
  async cachedRoles(): Promise<RolesByAddressType | null> {
    if (typeof window !== 'undefined') {
      if (this.roleDB) {
        const roles = await fetchAll(this.roleDB, ROLE_STORE);
        return {};
        // return roles.reduce(
        //   (roles: RolesByAddressType, rule) =>
        //     this.addPerm(
        //       roles,
        //       rule.namespace,
        //       rule.role,
        //       rule.resource,
        //       rule.permission,
        //       rule.expiresAt, // Already converted to milliseconds
        //     ),
        //   {},
        // );
      }
    }
    return null;
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
