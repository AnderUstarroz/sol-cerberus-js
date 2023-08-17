import {web3} from '@project-serum/anchor';
import {
  Keypair,
  PublicKey,
  Connection,
  ConfirmOptions,
  TransactionInstruction,
} from '@solana/web3.js';
import * as anchor from '@project-serum/anchor';
import {appPda, rulePda, rolePda, nftMetadataPda, seedPda} from '../pdas';
import {SolCerberus as SolCerberusTypes} from '../types/sol_cerberus';
import {SOL_CERBERUS_PROGRAM_ID} from '../constants';
import SolCerberusIDL from '../idl/sol_cerberus.json';
import {getAssociatedTokenAddress} from '@solana/spl-token';
import {BN} from '@project-serum/anchor';
import {
  getRoleDB,
  getRuleDB,
  RULE_STORE,
  bulkInsert,
  ROLE_STORE,
  fetchAll,
  dbExists,
  RoleType,
  getFromIndex,
  setDBConfig,
  getDBConfig,
} from '../db';
import {IDBPDatabase} from 'idb';
import {dateToRust, short_key} from '../utils';

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

export enum rolesGroupedBy {
  Address,
  Role,
  None,
}
export enum accountTypes {
  Basic = 0,
  Free = 1,
}

export enum cacheUpdated {
  Roles = 0,
  Rules = 1,
}

export enum addressTypes {
  Wallet = 'wallet',
  NFT = 'nft',
  Collection = 'collection',
}

export interface InitializeAppOptionsType {
  cached?: boolean;
  getIx?: boolean;
  confirmOptions?: ConfirmOptions;
}

export interface UpdateAppOptionsType
  extends Omit<InitializeAppOptionsType, 'appId'> {
  authority?: PublicKey;
}

export interface DeleteAppOptionsType
  extends Omit<InitializeAppOptionsType, 'cached'> {
  collector?: PublicKey;
}

export interface AssignRoleOptionsType {
  expiresAt?: Date | null;
  getIx?: boolean;
  confirmOptions?: ConfirmOptions;
}

export interface DeleteAssignedRoleOptionsType
  extends Omit<AssignRoleOptionsType, 'expiresAt'> {
  collector?: PublicKey;
}

export interface AddRuleOptionsType extends AssignRoleOptionsType {
  namespace?: namespaces;
}

export interface DeleteRuleOptionsType
  extends Omit<AssignRoleOptionsType, 'expiresAt'> {
  namespace?: namespaces;
  collector?: PublicKey;
}

export interface FetchPermsOptionsType {
  useCache?: boolean;
}

export interface AssignedRolesOptsType {
  useCache?: boolean;
  groupBy?: rolesGroupedBy;
}
export interface PermsType {
  [perm: string]: {
    expiresAt: number | null;
  };
}

export type AddressTypeType =
  keyof anchor.IdlTypes<SolCerberusTypes>['AddressType'];

export interface ResourcesType {
  [resource: string]: PermsType;
}

export interface RoleAccountFilterType {
  memcmp: {
    offset: number;
    bytes: string; // Address as base58 encoded string
  };
}
export interface RolesType {
  [role: string]: ResourcesType;
}

export interface CollectionsMintsType {
  [collectionAddress: string]: PublicKey[];
}
export interface CachedPermsType {
  [namespace: number]: RolesType;
}

export interface AssignedRoleObjectType {
  addressType: AddressTypeType;
  nftMints?: PublicKey[];
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

export interface DefaultAccountsType extends Partial<AccountsType> {}

export interface AccountsOptionsType {
  namespace?: namespaces;
  defaultAccounts?: DefaultAccountsType;
  useCPI?: boolean;
}
export interface SolCerberusOptionsType {
  appId?: PublicKey;
  appChangedCallback?: Function;
  rulesChangedCallback?: Function;
  rolesChangedCallback?: Function;
  permsAutoUpdate?: boolean;
  confirmOptions?: ConfirmOptions;
}

export type NFTAddressType = PublicKey;
export type CollectionAddressType = PublicKey;
export interface LoginOptionsType {
  nfts?: [NFTAddressType, CollectionAddressType][];
  wildcard?: boolean;
  useCache?: boolean;
}

export const newApp = (): PublicKey => web3.Keypair.generate().publicKey;

/**
 * Creates the Connection provider
 *
 * @param connection JSON RPC Connection
 * @param wallet The wallet used to pay for and sign all transactions.
 */
export function getProvider(
  connection: Connection,
  wallet: any,
  options: ConfirmOptions = {},
): anchor.Provider {
  return new anchor.AnchorProvider(connection, wallet.adapter ?? wallet, {
    ...anchor.AnchorProvider.defaultOptions(),
    ...options,
  });
}

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
  /** @internal */ #permsAutoUpdate: boolean = true; // Fetches and updates permissions when modified (only cached APPs)
  /** @internal */ #assignedRoles: AddressByRoleType = {};
  /** @internal */ #collectionsMints: CollectionsMintsType = {};

  /**
   * Creates Sol Cerberus client
   *
   * @param provider Connection provider
   * @param options Sol Cerberus config options:
   * ```
   * {
   *    appId: PublicKey // The ID identifying the Sol Cerberus APP (if empty a random one will be created)
   *    appChangedCallback?: Function // will be called whenever the app has changed
   *    rulesChangedCallback?: Function // will be called whenever a rule has changed
   *    rolesChangedCallback?: Function // will be called whenever a role has changed
   *    permsAutoUpdate?: boolean // Defines if the permissions (rules) should be automatically fetched when they change.
   *    confirmOptions: { //The RPC confirm options:
   *        skipPreflight?: boolean; // Disables transaction verification step
   *        commitment?: Commitment; //  Desired commitment level
   *        preflightCommitment?: Commitment; // Preflight commitment level
   *        maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *        minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *    }
   * }
   * ```
   */
  constructor(
    connection: Connection,
    wallet: any,
    options: SolCerberusOptionsType = {},
  ) {
    const provider = getProvider(connection, wallet);
    this.#appId = options.appId ?? Keypair.generate().publicKey;
    this.#program = new anchor.Program(
      SolCerberusIDL as any,
      SOL_CERBERUS_PROGRAM_ID,
      provider,
    );
    this.#wallet = provider.publicKey as PublicKey;
    this.#appListener = this.listenAppEvents(options);
    this.#rulesListener = this.listenRulesEvents(options);
    this.#rolesListener = this.listenRolesEvents(options);
    if (options.hasOwnProperty('permsAutoUpdate')) {
      this.#permsAutoUpdate = !!options.permsAutoUpdate;
    }
  }

  /**
   * Subscribes to Sol Cerberus App updates to refresh the app data
   * whenever the APP has been updated.
   */
  listenAppEvents(config: SolCerberusOptionsType) {
    return this.#program.addEventListener('AppChanged', async (event, slot) => {
      if (event.appId.toBase58() === this.appId.toBase58()) {
        // console.log('Refreshing APP DATA..');
        await this.fetchAppData(); // Refresh APP data
        if (this.#permsAutoUpdate && this.rulesHaveChanged()) {
          await this.fetchPerms();
        }
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
  listenRulesEvents(config: SolCerberusOptionsType) {
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
  listenRolesEvents(config: SolCerberusOptionsType) {
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
    this.#appPda = await appPda(this.#appId);
    return this.#appPda;
  }

  async fetchAppData() {
    try {
      this.#appData = await this.program.account.app.fetch(
        await this.getAppPda(),
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

  get assignedRoles() {
    return this.#assignedRoles;
  }

  set wallet(address: PublicKey) {
    this.#wallet = address;
  }

  useCache = (): boolean =>
    !!this.#appData?.cached && typeof window !== 'undefined';

  rolesHaveChanged = (): boolean =>
    this.useCache() &&
    this.#appData?.rolesUpdatedAt.toNumber() !== this.#roleDB?.version;

  rulesHaveChanged = (): boolean =>
    this.useCache() &&
    this.#appData?.rulesUpdatedAt.toNumber() !== this.#ruleDB?.version;

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
    resource: string,
    permission: string,
    namespace: number = namespaces.Rule,
  ) {
    return this.appData && this.isAuthority()
      ? true // Authority always has full access
      : !!this.findRule(this.assignedRoles, resource, permission, namespace);
  }

  hasRule(
    role: string,
    resource: string,
    permission: string,
    namespace: number = namespaces.Rule,
  ): boolean {
    const now = new Date().getTime();
    try {
      //@ts-ignore
      let perm = this.permissions[namespace][role][resource][permission];
      if (!perm.expiresAt || perm.expiresAt > now) {
        return true;
      }
    } catch (e) {}
    return false;
  }

  /**
   * Returns the first valid (not expired) assigned address
   */
  validAssignedAddress(addresses: AssignedAddressType): string | null {
    const now = new Date().getTime();
    for (const address in addresses) {
      if (
        !addresses[address].expiresAt ||
        (addresses[address].expiresAt as number) > now
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
      return await rulePda(this.appId, ...rule);
    } catch (e) {}

    return null;
  }

  parseAddressType(
    addressType: anchor.IdlTypes<SolCerberusTypes>['AddressType'],
  ): AddressTypeType {
    return Object.keys(addressType)[0] as AddressTypeType;
  }

  /**
   * Fetches the roles assigned to the provided address
   *
   * @param wallet The Public key used for authentication
   * @param options Defines the login options:
   * ```
   * {
   *    nfts: [[NFTAddressType, CollectionAddressType], ..] // List containing pairs of NFT mint and his corresponding Collection address.
   *    collectionAddress: PublicKey // The address of the Collection (only required when login via NFT Collection address)
   *    wildcard: boolean // Fetches or not the roles associated to all wallets via wildcard "*"
   * }
   * ```
   * @returns
   */
  async login(
    wallet: PublicKey,
    options: LoginOptionsType = {},
  ): Promise<AddressByRoleType> {
    options = {nfts: [], wildcard: true, useCache: true, ...options};
    let addresses: (PublicKey | null)[] = [wallet];
    // Fetch Roles assigned to all addresses (when using wildcard "*")
    if (options.wildcard) {
      addresses.push(null);
    }
    if (options.nfts?.length) {
      options.nfts.map(([nftAddress, collectionAddress]) => {
        // Add NFT address
        addresses.push(nftAddress);
        // Add Collection address
        addresses.push(collectionAddress);
        // Create collection mint address if not exists:
        if (!this.#collectionsMints[collectionAddress.toBase58()]) {
          this.#collectionsMints[collectionAddress.toBase58()] = [];
        }
        // Add corresponding nft mint addresses to the collection
        this.#collectionsMints[collectionAddress.toBase58()].push(nftAddress);
      });
    }

    this.setAssignedRoles(
      (await this.filterAssignedRoles(addresses, {
        useCache: options.useCache,
        groupBy: rolesGroupedBy.None,
      })) as RoleType[][],
    );
    this.#wallet = wallet;
    return this.assignedRoles;
  }

  /**
   * Set the assigned roles within the instance.
   *
   * @param newRoles List containing the list of roles corresponding to the provided addresses
   */
  setAssignedRoles = (newRoles: RoleType[][]) => {
    this.#assignedRoles = newRoles.reduce((assignedRoles, roles) => {
      for (let row of roles) {
        if (!assignedRoles[row.role]) {
          assignedRoles[row.role] = {};
        }
        assignedRoles[row.role][row.address] = {
          addressType: row.addressType,
          expiresAt: row.expiresAt,
        };
        if (row.addressType === addressTypes.Collection) {
          if (!this.#collectionsMints[row.address]) {
            throw new Error(
              `${short_key(row.address)} is a collection address! ` +
                'To login using a NFT collection address provide both the NFT mint and the collection address, e.g: sc.login(MY_WALLET, {nfts: [[MY_NFT_MINT, NFT_COLLECTION_MINT], ...]})',
            );
          }
          assignedRoles[row.role][row.address].nftMints =
            this.#collectionsMints[row.address];
        }
      }
      return assignedRoles;
    }, {} as AddressByRoleType);
  };

  /**
   * Clear all assigned roles added with the login() method.
   *
   * @returns boolean
   */
  flushAssignedRoles = () => {
    this.#assignedRoles = {};
    this.#collectionsMints = {};
    return true;
  };

  /**
   * Fetches the roles assigned to the provided addresses
   * @param accountsFilters Program accounts filters: https://solanacookbook.com/guides/get-program-accounts.html#deep-dive
   */
  async filterAssignedRoles(
    accountsFilters: (PublicKey | null)[],
    options: AssignedRolesOptsType,
  ): Promise<RolesByAddressType[] | RoleType[][]> {
    options = {useCache: true, groupBy: rolesGroupedBy.Address, ...options};
    return (
      await Promise.allSettled(
        accountsFilters.map((address: PublicKey | null) =>
          this.fetchAssignedRoles(
            [
              {
                memcmp: {
                  offset: address ? 41 : 40, // Starting byte of the Address Pubkey:41,
                  bytes: address ? address.toBase58() : '1', // Address as base58 encoded string or the wildcard * = '1'
                },
              },
            ],
            {
              useCache: options.useCache,
              groupBy: options.groupBy,
            },
          ),
        ),
      )
    )
      .filter((r: any) => r.status === 'fulfilled')
      .map((r: any) => r.value);
  }

  /**
   * Parses Roles into IDB rows with the following format:
   * ```
   * {
   *    role: 'TriangleMaster',
   *    address: '*',
   *    addressType: 'wallet',
   *    expiresAt: 1689033410616  // Time in milliseconds
   * }
   * ```
   *
   * @param fetchedRoles Roles accounts fetched from Solana
   * @returns
   */
  parseRoles = (
    fetchedRoles: anchor.ProgramAccount<
      anchor.IdlAccounts<SolCerberusTypes>['role']
    >[],
  ): RoleType[] =>
    fetchedRoles.map(r => ({
      address: r.account.address ? r.account.address.toBase58() : '*',
      addressType: this.parseAddressType(r.account.addressType),
      role: r.account.role,
      expiresAt: r.account.expiresAt
        ? r.account.expiresAt.toNumber() * 1000
        : null,
    }));

  /**
   * Fetches all assigned roles for the current program
   *
   * @param accountsFilters Program accounts filters: https://solanacookbook.com/guides/get-program-accounts.html#deep-dive
   * @param useCache Defines if cached should be used or not
   * @param groupByAddress When True returns roles grouped by address, otherwise returns addresses grouped by Roles.
   * @returns Roles (format depends on the options.groupBy used)
   */
  async fetchAssignedRoles(
    accountsFilters: RoleAccountFilterType[] = [],
    options: AssignedRolesOptsType = {},
  ): Promise<RolesByAddressType | AddressByRoleType | RoleType[]> {
    options = {useCache: true, groupBy: rolesGroupedBy.Address, ...options};
    const appData = await this.getAppData();
    const cachedAddresses = this.cachedAddresses(accountsFilters);
    let cached = appData?.cached
      ? await this.cachedRoles(
          cachedAddresses,
          appData.rolesUpdatedAt.toNumber(),
          options.groupBy,
        )
      : null;
    // console.log('CACHED ROLES:', cached);
    if (!options.useCache || !cached) {
      let fetched = this.parseRoles(
        await this.#program.account.role.all([
          {
            memcmp: {
              offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
              bytes: this.#appId.toBase58(), // base58 encoded string
            },
          },
          ...accountsFilters,
        ]),
      );
      // console.log('FETCHED FROM SOLANA:\n', fetched);
      cached = this.groupRoles(fetched, options.groupBy);
      if (this.useCache()) {
        // Include not found addresses to avoid repeating Solana requests in the future.
        if (cachedAddresses.length) {
          fetched = await this.includeNotFoundAddresses(
            cachedAddresses,
            fetched,
          );
        }
        this.setCachedRoles(fetched, !accountsFilters.length);
      }
    }
    return cached;
  }

  /**
   * Fetches all roles
   *
   * @param options
   * @returns Roles (format depends on the options.groupBy used)
   */
  fetchAllRoles = async (
    options: AssignedRolesOptsType = {},
  ): Promise<RolesByAddressType | AddressByRoleType | RoleType[]> =>
    await this.fetchAssignedRoles([], options);

  includeNotFoundAddresses = async (
    cachedAddresses: string[],
    fetched: RoleType[],
  ) => {
    const addresses = new Set(cachedAddresses);
    // Remove existing addresses
    for (let r of fetched) {
      if (addresses.delete(r.address) && !addresses) {
        break;
      }
    }
    // Add not found addresses
    for (let addr of addresses) {
      fetched.push({
        address: addr,
        addressType: 'wallet',
        role: '',
        expiresAt: null,
      });
    }
    return fetched;
  };

  /**
   *
   * @param fetchedRoles Fetched roles
   * @returns Addresses grouped by roles
   */
  groupByRole = (fetchedRoles: RoleType[]): AddressByRoleType =>
    fetchedRoles.reduce((result, role) => {
      if (!result[role.role]) {
        result[role.role] = {};
      }
      result[role.role][role.address] = {
        addressType: role.addressType,
        expiresAt: role.expiresAt,
      };
      // Add collection mint
      if (
        role.addressType === addressTypes.Collection &&
        this.#collectionsMints[role.address]
      ) {
        result[role.role][role.address].nftMints =
          this.#collectionsMints[role.address];
      }

      return result;
    }, {} as RolesByAddressType);

  /**
   *
   * @param fetchedRoles Fetched roles
   * @returns Roles grouped by address, E.G:
   * ```
   * {
   *    Ak94...2Uat: {
   *      role1:  {
   *        addressType: "nft"
   *        nftMints?: [PublicKey, PublicKey, ..]
   *        expiresAt: 103990020
   *      },
   *      role2:  {...}
   *    },
   *    ekB12...tR38: {...}
   * }
   * ```
   */
  groupByAddress = (fetchedRoles: RoleType[]): RolesByAddressType =>
    fetchedRoles.reduce((result, role) => {
      if (!result.hasOwnProperty(role.address)) {
        result[role.address] = {};
      }
      result[role.address][role.role] = {
        addressType: role.addressType,
        expiresAt: role.expiresAt,
      };
      // Add NFTMint for collections
      if (
        role.addressType === addressTypes.Collection &&
        this.#collectionsMints[role.address]
      ) {
        result[role.address][role.role].nftMints =
          this.#collectionsMints[role.address];
      }

      return result;
    }, {} as RolesByAddressType);

  /**
   * Parse Roles grouping by Role or Address:
   *
   */
  groupRoles(
    parsedRoles: RoleType[],
    groupBy: rolesGroupedBy = rolesGroupedBy.Address,
  ): RolesByAddressType | AddressByRoleType | RoleType[] {
    return groupBy === rolesGroupedBy.Address
      ? this.groupByAddress(parsedRoles)
      : groupBy === rolesGroupedBy.Role
      ? this.groupByRole(parsedRoles)
      : parsedRoles;
  }

  async getDefaultAccounts(useCPI: boolean): Promise<AccountsType> {
    let accs = {
      solCerberusApp: await this.getAppPda(), // Fetched
      solCerberusRole: null,
      solCerberusRule: null,
      solCerberusToken: null,
      solCerberusMetadata: null,
      solCerberusSeed: null,
    } as AccountsType;
    // Cross-Program Invocations (CPI) require Sol Cerberus program account.
    if (useCPI) {
      accs.solCerberus = this.program.programId;
    }
    return accs;
  }

  /**
   * Generates the required account PDAs to perform the provided transaction.
   *
   * @param resource The resource trying to
   * @param permission The permission required to access the resource
   * @param options special settings for fetching accounts: {
   *    namespace?: Integer representing the kind of permission.
   *    useCPI?: Boolean,
   *    defaultAccounts?: Object containing already fetched accounts PDA (to avoid duplicating requests)
   *  }
   *
   * @returns The fetched accounts, for instance:
   * ```
   * {
   *    solCerberusApp: app PDA,
   *    solCerberusRule: rule PDA,
   *    solCerberusRole: role PDA,
   *    solCerberusToken: tokenAccount PDA,
   *    solCerberusMetadata: Metaplex PDA,
   *    solCerberusSeed: Seed PDA,
   *    solCerberus: Program PDA,
   * }
   * ```
   */
  async accounts(
    resource: string,
    permission: string,
    options: AccountsOptionsType = {},
  ): Promise<AccountsType> {
    options = {namespace: namespaces.Rule, useCPI: true, ...options};
    await this.getPermissions(); // Ensures that APP and perms are fetched.
    let defaultOutput = {
      ...(await this.getDefaultAccounts(options.useCPI !== false)),
      ...(options.defaultAccounts ?? {}),
    };
    if (this.isAuthority()) return defaultOutput;
    try {
      const rule = this.findRule(
        this.assignedRoles,
        resource,
        permission,
        options.namespace,
      );
      if (!rule) {
        return {...defaultOutput, solCerberusSeed: await seedPda(this.wallet)};
      }
      const [roleFound, resourceFound, PermissionFound, ns] = rule;
      const validAddress = this.validAssignedAddress(
        this.assignedRoles[roleFound],
      );
      if (validAddress) {
        return await this.fetchPdaAccounts(
          this.assignedRoles,
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
    if (!defaultOutput.solCerberusRule) {
      asyncFuncs.push(async () => [
        'solCerberusRule',
        await rulePda(this.appId, role, resource, permission, namespace),
      ]);
    }
    // Role PDA fetcher
    if (!defaultOutput.solCerberusRole) {
      asyncFuncs.push(async () => [
        'solCerberusRole',
        await rolePda(this.appId, role, new PublicKey(assignedAddress)),
      ]);
    }
    // tokenAccount PDA fetcher
    if (!defaultOutput.solCerberusToken) {
      asyncFuncs.push(
        async () =>
          await this.getTokenAccount(
            roles[role][assignedAddress],
            assignedAddress,
          ),
      );
    }
    // Metadata PDA fetcher (optional)
    if (!defaultOutput.solCerberusMetadata) {
      asyncFuncs.push(
        async () => await this.getMetadataAccount(roles[role][assignedAddress]),
      );
    }
    // Seed PDA fetcher
    if (!defaultOutput.solCerberusSeed) {
      asyncFuncs.push(async () => [
        'solCerberusSeed',
        await seedPda(this.wallet),
      ]);
    }
    (await Promise.allSettled(asyncFuncs.map(f => f()))).map(
      (pdaRequest: any) => {
        if (pdaRequest.status === 'fulfilled') {
          // @ts-ignore
          defaultOutput[pdaRequest.value[0]] = pdaRequest.value[1];
        }
      },
    );
    // console.log('Fetched accounts:', defaultOutput);
    return defaultOutput;
  }

  /**
   * Adds NFT fetcher (only needed when using NFT authentication)
   */
  async getTokenAccount(
    assignedRole: AssignedRoleObjectType,
    assignedAddress: string,
  ): Promise<[string, PublicKey | null]> {
    let tokenAcc: [string, PublicKey | null] = ['solCerberusToken', null];
    if (assignedRole.addressType === 'nft') {
      tokenAcc[1] = await getAssociatedTokenAddress(
        new PublicKey(assignedAddress),
        this.wallet,
      );
    } else if (assignedRole.addressType === 'collection') {
      if (!assignedRole.nftMints) {
        throw new Error(
          `Missing NFT Mint addresses for collection: "${assignedAddress}"`,
        );
      }
      tokenAcc[1] = await getAssociatedTokenAddress(
        assignedRole.nftMints[0],
        this.wallet,
      );
    }
    return tokenAcc;
  }

  /**
   * Creates Rule DB or returns the already existing one.
   * Returns Boolean (True when DB created, False otherwise)
   */
  async createRuleDB(version: number): Promise<boolean> {
    const exists =
      !this.ruleDB && (await dbExists(this.appId.toBase58(), 'Rule', version));
    this.#ruleDB = await getRuleDB(this.appId.toBase58(), version);
    return exists;
  }

  /**
   * Creates Role DB or returns the already existing one.
   * Returns Boolean (True when DB created, False otherwise)
   */
  async createRoleDB(version: number): Promise<boolean> {
    const exists =
      !this.roleDB && (await dbExists(this.appId.toBase58(), 'Role', version));
    this.#roleDB = await getRoleDB(this.appId.toBase58(), version);
    return exists;
  }

  /**
   * Adds NFT fetcher (only needed when using NFT authentication)
   */
  async getMetadataAccount(
    assignedRole: AssignedRoleObjectType,
  ): Promise<[string, PublicKey | null]> {
    let metadataAcc: [string, PublicKey | null] = ['solCerberusMetadata', null];
    if (
      assignedRole.addressType === 'collection' &&
      assignedRole.nftMints?.length
    ) {
      metadataAcc[1] = await nftMetadataPda(
        assignedRole.nftMints[0] as PublicKey,
      );
    }
    return metadataAcc;
  }

  /*
   * Fetches Permissions from blockchain
   *
   * @param options: Additional parameters to customize behavior:
   *
   * ```
   * {
   *   useCache: boolean // Wether the rules must be fetched from cache or not.
   * }
   * ```
   */
  async fetchPerms(options: FetchPermsOptionsType = {}) {
    options = {useCache: true, ...options};
    const appData = await this.getAppData();
    let cached = appData?.cached
      ? await this.cachedPerms(appData.rulesUpdatedAt.toNumber())
      : null;
    // console.log('CACHED RULES:', cached);
    // Fetch perms only if they have been modified
    if (!options.useCache || !cached) {
      let fetched = await this.#program.account.rule.all([
        {
          memcmp: {
            offset: 8, // APP ID Starting byte (first 8 bytes is the account discriminator)
            bytes: this.#appId.toBase58(), // base58 encoded string
          },
        },
      ]);
      cached = this.parsePerms(fetched);
      if (this.useCache()) {
        this.setCachedPerms(fetched);
      }
    }
    this.#permissions = cached;
    return cached;
  }

  /**
   * Parse Permissions into following mapped format:
   *```
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
   * ```
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
    // console.log('Storing perms:', fetchedPerms);
    bulkInsert(
      this.ruleDB as IDBPDatabase<unknown>,
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

  /**
   * Retrieves Perms from IDB (When available)
   */
  async cachedPerms(version: number): Promise<CachedPermsType | null> {
    if (this.useCache()) {
      if (this.rulesHaveChanged()) {
        if (!(await this.createRuleDB(version))) {
          return null;
        }
      }
      const rules = await fetchAll(
        this.ruleDB as IDBPDatabase<unknown>,
        RULE_STORE,
      );
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
    return null;
  }

  /**
   * Stores Roles on IDB (When available)
   */
  async setCachedRoles(parsedRoles: RoleType[], fullyFetched: boolean = false) {
    // console.log('Storing roles:', parsedRoles);
    if (fullyFetched) {
      await setDBConfig(this.roleDB as IDBPDatabase<unknown>, {
        fullyFetched: true,
      });
    }
    bulkInsert(this.roleDB as IDBPDatabase<unknown>, ROLE_STORE, parsedRoles);
  }

  isFullyFetched = async (
    db: IDBPDatabase<unknown> | null,
  ): Promise<boolean> => {
    return db ? (await getDBConfig(db)).fullyFetched : false;
  };

  /**
   *
   * @param accountsFilters
   * @returns array of strings containing the addresses (or wildcards "*") used as filters
   */
  cachedAddresses = (accountsFilters: RoleAccountFilterType[]): string[] =>
    accountsFilters
      .filter(f => 41 >= f.memcmp?.offset && 40 <= f.memcmp?.offset)
      .map(f => (f.memcmp.bytes === '1' ? '*' : f.memcmp.bytes));

  /**
   * Retrieves Roles from IDB (When available)
   * @param key when defined returns specific rows
   */
  async cachedRoles(
    keys: string[],
    version: number,
    groupBy: rolesGroupedBy = rolesGroupedBy.Address,
  ): Promise<RolesByAddressType | AddressByRoleType | RoleType[] | null> {
    if (this.useCache()) {
      if (this.rolesHaveChanged()) {
        if (!(await this.createRoleDB(version))) {
          return null;
        }
      }
      // Either fetch specific Addresses or all of them:
      let roles = keys.length
        ? (
            await Promise.allSettled(
              keys.map((address: string) =>
                getFromIndex(
                  this.roleDB as IDBPDatabase<unknown>,
                  ROLE_STORE,
                  'address',
                  address,
                ),
              ),
            )
          )
            .filter((r: any) => r.status === 'fulfilled')
            .reduce((result: any, rows: any) => {
              for (let item of rows.value) {
                result.push(item);
              }
              return result;
            }, [])
        : await fetchAll(this.roleDB as IDBPDatabase<unknown>, ROLE_STORE);

      // Filtered search must return null when empty
      // Otherwise it won't fetch data from Solana.
      if (!roles.length && !(await this.isFullyFetched(this.roleDB))) {
        return null;
      }
      // NotFound addresses must be filtered out
      if (keys.length) {
        roles = roles.filter((r: RoleType) => r.role);
      }
      return this.groupRoles(roles, groupBy);
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
   * Disconnect websockets
   */
  disconnect() {
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

  /**
   * Initializes a Sol Cerberus APP
   *
   * @param name Name to identify the APP
   * @param recovery The backup wallet (null for none)
   * @param options Settings:
   * ```
   * {
   *    cached: boolean // Wether the Roles and Permissions should be cached on client side
   *    getIx: boolean //Returns the instruction instead of executing the command on Solana's RPC
   *    confirmOptions: { //The RPC confirm options:
   *          skipPreflight?: boolean; // Disables transaction verification step
   *          commitment?: Commitment; //  Desired commitment level
   *          preflightCommitment?: Commitment; // Preflight commitment level
   *          maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *          minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *        }
   *  }
   * ```
   */
  async initializeApp(
    name: string,
    recovery: PublicKey | null = null,
    options: InitializeAppOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    options = {cached: true, ...options};
    const method = this.program.methods
      .initializeApp({
        id: this.appId,
        name: name,
        recovery: recovery,
        cached: options.cached as boolean,
      })
      .accounts({
        app: await this.getAppPda(),
      });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Updates a Sol Cerberus APP
   *
   * @param name Name to identify the APP
   * @param recovery The backup wallet (null for none)
   * @param options Settings:
   * ```
   * {
   *    authority: PublicKey // Updates the authority of the Sol Cerberus APP
   *    cached: boolean // Wether the Roles and Permissions should be cached on client side
   *    getIx: boolean //Returns the instruction instead of executing the command on Solana's RPC
   *    confirmOptions: { //The RPC confirm options:
   *          skipPreflight?: boolean; // Disables transaction verification step
   *          commitment?: Commitment; //  Desired commitment level
   *          preflightCommitment?: Commitment; // Preflight commitment level
   *          maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *          minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *        }
   *  }
   * ```
   */
  async updateApp(
    name: string,
    recovery: PublicKey | null = null,
    options: UpdateAppOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    const app = await this.getAppData();
    if (!app) {
      throw new Error('Sol Cerberus App not found!');
    }
    const method = this.program.methods
      .updateApp({
        name: name,
        authority: options.authority ?? app.authority,
        recovery: recovery,
        cached: options.cached ?? app.cached,
        fee: app.fee,
        accountType: app.accountType,
        expiresAt: app.expiresAt,
      })
      .accounts({
        app: await this.getAppPda(),
      });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Delete Sol Cerberus APP
   *
   * @param options Settings:
   * ```
   * {
   *    collector?: PublicKey // The wallet receiving the funds (defaults to authority)
   *    getIx?: boolean //Returns the instruction instead of executing the command on Solana's RPC
   *    confirmOptions?: { //The RPC confirm options:
   *          skipPreflight?: boolean; // Disables transaction verification step
   *          commitment?: Commitment; //  Desired commitment level
   *          preflightCommitment?: Commitment; // Preflight commitment level
   *          maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *          minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *        }
   *  }
   * ```
   */
  async deleteApp(
    options: DeleteAppOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    const method = this.program.methods.deleteApp().accounts({
      app: await this.getAppPda(),
      collector: options.collector ?? this.wallet,
    });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Assign a Role to the provided address or to all addresses ("*")
   *
   * @param role String representing the role to assign
   * @param addressType Either 'wallet', 'nft' or 'collection'
   * @param address The Solana address (or wildcard "*") to which the role is assigned. The wilcard "*" means that role will be applied to everyone.
   * @param options Settings:
   * ```
   * {
   *    expiresAt: Date //The time at which the role won't be valid anymore
   *    getIx: boolean //Returns the instruction instead of executing the command on Solana's RPC
   *    confirmOptions: { //The RPC confirm options:
   *          skipPreflight?: boolean; // Disables transaction verification step
   *          commitment?: Commitment; //  Desired commitment level
   *          preflightCommitment?: Commitment; // Preflight commitment level
   *          maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *          minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *        }
   *  }
   * ```
   */
  async assignRole(
    role: string,
    addressType: addressTypes,
    address: PublicKey | string,
    options: AssignRoleOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    options = {...{expiresAt: null, getIx: false}, ...options}; // Default options
    const assignedAddress =
      typeof address !== 'string'
        ? address
        : address === '*'
        ? null
        : new PublicKey(address);

    const method = this.program.methods
      .assignRole({
        role: role,
        addressType: {[addressType]: {}} as any,
        address: assignedAddress,
        expiresAt: options.expiresAt ? dateToRust(options.expiresAt) : null,
      })
      .accounts({
        role: await rolePda(this.appId, role, assignedAddress),
        ...(await this.accounts(addressType, role, {
          namespace: namespaces.AssignRole,
          useCPI: false,
        })),
      });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Delete the Role assigned to the provided address or to wildcard "*" (all addresses)
   *
   * @param role String: The role name.
   * @param addressType Either 'wallet', 'nft' or 'collection'
   * @param address String | PubKey: The Solana address (or wildcard "*") to which the role is assigned.
   * @param options Settings:
   * ```
   * {
   *      collector?: PublicKey // The wallet receiving the funds (defaults to authority)
   *      getIx?: boolean // Returns the instruction instead of executing the command on Solana's RPC
   *      confirmOptions?: { // The RPC confirm options:
   *            skipPreflight?: boolean; // Disables transaction verification step
   *            commitment?: Commitment; //  Desired commitment level
   *            preflightCommitment?: Commitment; // Preflight commitment level
   *            maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *            minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *      }
   * }
   * ```
   */
  async deleteAssignedRole(
    role: string,
    addressType: addressTypes,
    address: PublicKey | string,
    options: DeleteAssignedRoleOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    options = {...{getIx: false}, ...options}; // Default options
    const assignedAddress =
      typeof address !== 'string'
        ? address
        : address === '*'
        ? null
        : new PublicKey(address);
    const method = this.program.methods.deleteAssignedRole().accounts({
      role: await rolePda(this.appId, role, assignedAddress),
      collector: options.collector ?? this.wallet,
      ...(await this.accounts(addressType, role, {
        namespace: namespaces.DeleteAssignRole,
        useCPI: false,
      })),
    });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Create new Rule/Permission
   *
   * @param role The role getting the permission
   * @param resource The resource in which the permission will have effect
   * @param permission The permission
   * @param options Settings:
   * ```
   * {
   *      namespace: integer // Defines the type of rules: 0: Default rule, 1: AssignRole rule, etc..
   *      expiresAt: Date // The time at which the rule won't be valid anymore
   *      getIx: boolean // Returns the instruction instead of executing the command on Solana's RPC
   *      confirmOptions: { // The RPC confirm options:
   *            skipPreflight?: boolean; // Disables transaction verification step
   *            commitment?: Commitment; //  Desired commitment level
   *            preflightCommitment?: Commitment; // Preflight commitment level
   *            maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *            minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *          }
   *    }
   * ```
   */
  async addRule(
    role: string,
    resource: string,
    permission: string,
    options: AddRuleOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    options = {
      namespace: namespaces.Rule,
      expiresAt: null,
      getIx: false,
      ...options,
    }; // Default options
    // Fetch accounts and RULE for NS and Role (verifies if current user is allowed to delete a rule using this Namespace and Role)
    let {solCerberusRule, ...accounts} = await this.accounts(
      (options.namespace as namespaces).toString(),
      role,
      {
        namespace: namespaces.DeleteRuleNSRole,
        useCPI: false,
      },
    );
    // Fetch RULE for Resource and Permission (verifies if current user is allowed to delete a rule using this Resource and Permission)
    let {solCerberusRule: solCerberusRule2} = await this.accounts(
      resource,
      role,
      {
        namespace: namespaces.DeleteRuleResourcePerm,
        useCPI: false,
        defaultAccounts: accounts, // Reuse fetched accounts
      },
    );
    const method = this.program.methods
      .addRule({
        namespace: options.namespace as namespaces,
        role: role,
        resource: resource,
        permission: permission,
        expiresAt: options.expiresAt ? dateToRust(options.expiresAt) : null,
      })
      .accounts({
        rule: await rulePda(this.appId, role, resource, permission),
        solCerberusRule: solCerberusRule,
        solCerberusRule2: solCerberusRule2,
        ...accounts,
      });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }

  /**
   * Delete Rule/Permission
   *
   * @param role The role name
   * @param resource The resource name
   * @param permission The permission name
   * @param options Settings:
   * ```
   * {
   *      namespace?: integer // Defines the type of rules: 0: Default rule, 1: AssignRole rule, etc..
   *      collector?: PublicKey // The wallet receiving the funds (defaults to authority)
   *      getIx?: boolean Returns the instruction instead of executing the command on Solana's RPC
   *      confirmOptions?: { // The RPC confirm options:
   *            skipPreflight?: boolean; // Disables transaction verification step
   *            commitment?: Commitment; //  Desired commitment level
   *            preflightCommitment?: Commitment; // Preflight commitment level
   *            maxRetries?: number; //  Maximum number of times for the RPC node to retry
   *            minContextSlot?: number; //The minimum slot that the request can be evaluated at
   *      }
   * }
   * ```
   */
  async deleteRule(
    role: string,
    resource: string,
    permission: string,
    options: DeleteRuleOptionsType = {},
  ): Promise<string | TransactionInstruction> {
    options = {namespace: namespaces.Rule, getIx: false, ...options}; // Default options
    // Fetch accounts and RULE for NS and Role (verifies if current user is allowed to create a rule using this Namespace and Role)
    let {solCerberusRule, ...accounts} = await this.accounts(
      (options.namespace as namespaces).toString(),
      role,
      {
        namespace: namespaces.AddRuleNSRole,
        useCPI: false,
      },
    );
    // Fetch RULE for Resource and Permission (verifies if current user is allowed to create a rule using this Resource and Permission)
    let {solCerberusRule: solCerberusRule2} = await this.accounts(
      resource,
      role,
      {
        namespace: namespaces.AddRuleResourcePerm,
        useCPI: false,
        defaultAccounts: accounts, // Reuse fetched accounts
      },
    );
    const method = this.program.methods.deleteRule().accounts({
      rule: await rulePda(this.appId, role, resource, permission),
      solCerberusRule: solCerberusRule,
      solCerberusRule2: solCerberusRule2,
      collector: options.collector ?? this.wallet,
      ...accounts,
    });

    return await (options.getIx
      ? method.instruction()
      : method.rpc(options.confirmOptions ?? undefined));
  }
}
