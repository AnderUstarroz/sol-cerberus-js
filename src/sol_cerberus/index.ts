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
  ROLE_STORE,
  fetchAll,
  dbExists,
  RoleType,
  getFromIndex,
  setDBConfig,
  getDBConfig,
} from '../db';
import {IDBPDatabase} from 'idb';
import {short_key} from '../utils';

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

export enum cacheUpdated {
  Roles = 0,
  Rules = 1,
}

export enum addressTypes {
  Wallet = 'wallet',
  NFT = 'nft',
  Collection = 'collection',
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
  [collectionAddress: string]: string;
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
  permsAutoUpdate?: boolean;
}

export interface LoginConfig {
  collectionAddress?: PublicKey;
  wildcard?: boolean;
  useCache?: boolean;
}

export const new_sc_app = (): PublicKey => web3.Keypair.generate().publicKey;

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
  /** @internal */ #permsAutoUpdate: boolean = true; // Fetches and updates permissions (when modified)
  /** @internal */ #assignedRoles: AddressByRoleType = {};
  /** @internal */ #collectionsMints: CollectionsMintsType = {};

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
    if (config.hasOwnProperty('permsAutoUpdate')) {
      this.#permsAutoUpdate = !!config.permsAutoUpdate;
    }
  }

  /**
   * Subscribes to Sol Cerberus App updates to refresh the app data
   * whenever the APP has been updated.
   */
  listenAppEvents(config: ConfigType) {
    return this.#program.addEventListener('AppChanged', async (event, slot) => {
      if (event.appId.toBase58() === this.appId.toBase58()) {
        console.log('Refreshing APP DATA..');
        this.fetchAppData(); // Refresh APP data
        if (this.#permsAutoUpdate && this.rulesHaveChanged()) {
          this.fetchPerms();
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
      console.log(
        'Previous APP DATA: ',
        this.appData?.rulesUpdatedAt.toNumber(),
      );
      this.#appData = await this.program.account.app.fetch(
        await this.getAppPda(),
      );
      console.log('New APP DATA: ', this.appData?.rulesUpdatedAt.toNumber());
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

  parseAddressType(
    addressType: anchor.IdlTypes<SolCerberusTypes>['AddressType'],
  ): AddressTypeType {
    return Object.keys(addressType)[0] as AddressTypeType;
  }

  /**
   * Fetches the roles assigned to the provided address
   *
   * @param address The Public key used for authentication
   * @param config Defines the login options:
   *  - collectionAddress: The address of the Collection (only required when login via NFT Collection address)
   *  - wildcard: Fetches the roles associated to all wallets via wildcard "*"
   *
   * @returns
   */
  async login(
    address: PublicKey | null,
    config: LoginConfig = {},
  ): Promise<AddressByRoleType> {
    config = {wildcard: true, useCache: true, ...config};
    let addresses: (PublicKey | null)[] = [address];
    // Login via address (Wallet or NFT)
    if (address) {
      // Fetch Roles assigned to all addresses (when using wildcard "*")
      if (config.wildcard) {
        addresses.push(null);
      }
      // Login via NFT
      if (address.toBase58() !== this.wallet.toBase58()) {
        // Collection is mandatory when login via NFT
        if (!config.collectionAddress) {
          throw new Error(
            `${short_key(address)} is missing the collection address! ` +
              'To login via NFT please provide both the NFT mint and the collection address, e.g: sc.login(MY_NFT_PUBKEY, {collectionAddress: NFT_COLLECTION_PUBKEY})',
          );
        }
        // Add wallet address
        addresses.push(this.wallet);
        // Add Collection address
        this.setCollectionsMints({
          [config.collectionAddress.toBase58()]: address.toBase58(),
        }); // Add collection Mint
        addresses.push(config.collectionAddress);
      }

      // Login via wildcard "*"
    } else {
      // Add the wallet address
      addresses.push(this.wallet);
    }

    this.addAssignedRoles(
      (await this.filterAssignedRoles(
        addresses,
        config.useCache,
        rolesGroupedBy.None,
      )) as RoleType[][],
    );
    return this.assignedRoles;
  }

  /**
   * Add login roles to the assigned roles.
   *
   * @param newRoles List containing the list of roles corresponding to the provided addresses
   */
  addAssignedRoles = (newRoles: RoleType[][]) => {
    newRoles.map(roles =>
      roles.map(row => {
        if (!this.#assignedRoles[row.role]) {
          this.#assignedRoles[row.role] = {};
        }
        let nftMint = null;
        if (row.addressType === addressTypes.Collection) {
          if (!this.#collectionsMints[row.address]) {
            throw new Error(
              `${short_key(row.address)} is a collection address! ` +
                'To login using a NFT collection address provide both the NFT mint and the collection address, e.g: sc.login(MY_NFT_MINT, {collectionAddress: NFT_COLLECTION_MINT})',
            );
          }
          nftMint = new PublicKey(this.#collectionsMints[row.address]);
        }
        this.#assignedRoles[row.role][row.address] = {
          addressType: row.addressType,
          nftMint: nftMint,
          expiresAt: row.expiresAt,
        };
      }),
    );
  };

  /**
   * Sets the Collections mints
   *
   * @param collectionsMints Collection addresses as keys, Mint addresses as values
   *  E.G:
   *    {
   *      "FriELggez2Dy3phZeHHAdpcoEXkKQVkv6tx3zDtCVP8T": "BUGuuhPsHpk8YZrL2GctsCtXGneL1gmT5zYb7eMHZDWf",
   *      ...
   *    }
   *
   */
  setCollectionsMints = (collectionsMints: CollectionsMintsType) =>
    Object.entries(collectionsMints).map(
      ([collection, mint]) => (this.#collectionsMints[collection] = mint),
    );

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
    useCache: boolean = true,
    groupBy: rolesGroupedBy = rolesGroupedBy.Address,
  ): Promise<RolesByAddressType[] | RoleType[][]> {
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
            useCache,
            groupBy,
          ),
        ),
      )
    )
      .filter((r: any) => r.status === 'fulfilled')
      .map((r: any) => r.value);
  }

  /**
   * Parses Roles into IDB rows with the following format:
   *
   * {
   *    role: 'TriangleMaster',
   *    address: '*',
   *    addressType: 'wallet',
   *    expiresAt: 1689033410616  // Time in milliseconds
   * }
   *
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
   *
   */
  async fetchAssignedRoles(
    accountsFilters: RoleAccountFilterType[] = [],
    useCache: boolean = true,
    groupBy: rolesGroupedBy = rolesGroupedBy.Address,
  ): Promise<RolesByAddressType | AddressByRoleType | RoleType[]> {
    const appData = await this.getAppData();
    const cachedAddresses = this.cachedAddresses(accountsFilters);
    let cached = appData?.cached
      ? await this.cachedRoles(
          cachedAddresses,
          appData.rolesUpdatedAt.toNumber(),
          groupBy,
        )
      : null;
    console.log('CACHED ROLES:', cached);
    if (!useCache || !cached) {
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
      console.log('FETCHED FROM SOLANA:\n', fetched);
      cached = this.groupRoles(fetched, groupBy);
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
      const nftMint =
        role.addressType === addressTypes.Collection &&
        this.#collectionsMints[role.address]
          ? new PublicKey(this.#collectionsMints[role.address])
          : null;
      result[role.role][role.address] = {
        addressType: role.addressType,
        nftMint: nftMint,
        expiresAt: role.expiresAt,
      };

      return result;
    }, {} as RolesByAddressType);

  /**
   *
   * @param fetchedRoles Fetched roles
   * @returns Roles grouped by address, E.G:
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
   *
   */
  groupByAddress = (fetchedRoles: RoleType[]): RolesByAddressType =>
    fetchedRoles.reduce((result, role) => {
      if (!result.hasOwnProperty(role.address)) {
        result[role.address] = {};
      }
      const nftMint =
        role.addressType === addressTypes.Collection &&
        this.#collectionsMints[role.address]
          ? new PublicKey(this.#collectionsMints[role.address])
          : null;
      result[role.address][role.role] = {
        addressType: role.addressType,
        nftMint: nftMint,
        expiresAt: role.expiresAt,
      };
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
    if (
      namespace >= namespaces.AddRuleNSRole &&
      namespace <= namespaces.DeleteRuleResourcePerm
    ) {
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
    asyncFuncs.push(async () => [
      'solCerberusRule',
      sc_rule_pda(this.appId, role, resource, permission, namespace),
    ]);
    // Role PDA fetcher
    asyncFuncs.push(async () => [
      'solCerberusRole',
      sc_role_pda(this.appId, role, new PublicKey(assignedAddress)),
    ]);
    // tokenAccount PDA fetcher
    asyncFuncs.push(async () =>
      this.getTokenAccount(roles[role][assignedAddress], assignedAddress),
    );
    // Metadata PDA fetcher (optional)
    asyncFuncs.push(async () =>
      this.getMetadataAccount(roles[role][assignedAddress]),
    );

    // Seed PDA fetcher
    asyncFuncs.push(async () => ['solCerberusSeed', sc_seed_pda(this.wallet)]);

    (await Promise.allSettled(asyncFuncs.map(f => f()))).map(
      (pdaRequest: any) => {
        if (pdaRequest.status === 'fulfilled') {
          // @ts-ignore
          defaultOutput[pdaRequest.value[0]] = pdaRequest.value[1];
        }
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
      return [
        'solCerberusToken',
        getAssociatedTokenAddress(assignedRole.nftMint, this.wallet),
      ];
    }
    return ['solCerberusToken', null];
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
  async getMetadataAccount(assignedRole: AssignedRoleObjectType) {
    if (assignedRole.addressType === 'collection') {
      return [
        'solCerberusMetadata',
        nft_metadata_pda(assignedRole.nftMint as PublicKey),
      ];
    }
    return ['solCerberusMetadata', null];
  }

  /*
   * Fetches Permissions from blockchain
   */
  async fetchPerms(useCache: boolean = true) {
    const appData = await this.getAppData();
    let cached = appData?.cached
      ? await this.cachedPerms(appData.rulesUpdatedAt.toNumber())
      : null;
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
      if (this.useCache()) {
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
    console.log('Storing perms:', fetchedPerms);
    bulk_insert(
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
    console.log('Storing roles:', parsedRoles);
    if (fullyFetched) {
      await setDBConfig(this.roleDB as IDBPDatabase<unknown>, {
        fullyFetched: true,
      });
    }
    bulk_insert(this.roleDB as IDBPDatabase<unknown>, ROLE_STORE, parsedRoles);
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
      let roles = keys
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
        console.log('Roles without filter: ', roles);
        roles = roles.filter((r: RoleType) => r.role);
        console.log('Roles after filter: ', roles);
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
