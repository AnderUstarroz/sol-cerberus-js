import {IDBPDatabase, openDB} from 'idb';

export const CONFIG_STORE = 'ConfigStore';
export const ROLE_STORE = 'RoleStore';
export const RULE_STORE = 'RuleStore';

export interface RoleType {
  role: string;
  address: string;
  addressType: 'wallet' | 'nft' | 'collection';
  expiresAt: number | null;
}
export interface RuleType {
  namespace: number;
  role: string;
  resource: string;
  permission: string;
  expiresAt: number | null;
}

export interface NewConfigType {
  fullyFetched: boolean;
}

export type DBType = 'Rule' | 'Role';

export const get_db_name = (appId: string, type: DBType): string =>
  `SolCerberus${type}DB_${appId.slice(0, 7)}`;

export type StoresType = typeof RULE_STORE | typeof ROLE_STORE;

export const deleteObjectStores = (db: IDBPDatabase, stores: string[]) => {
  let existingStores = Object.values(db.objectStoreNames);
  stores.map(store => {
    if (existingStores.includes(store)) {
      db.deleteObjectStore(store);
    }
  });
};

export const getRoleDB = async (appId: string, version: number) =>
  await openDB(get_db_name(appId, 'Role'), version, {
    upgrade(db, _oldVersion, _newVersion, _transaction) {
      // Erase all previous data when using a new DB version
      deleteObjectStores(db, [CONFIG_STORE, ROLE_STORE]);
      var configStore = db.createObjectStore(CONFIG_STORE);
      configStore.put({fullyFetched: false}, 'Settings');

      /**
       * Role store contains:
       *  - address
       *  - role
       *  - addressType
       *  - expiresAt
       */
      var roleStore = db.createObjectStore(ROLE_STORE, {autoIncrement: true});
      roleStore.createIndex('compoundIndex', ['address', 'role'], {
        unique: true,
      });
    },
  });

export const getRuleDB = async (appId: string, version: number) =>
  await openDB(get_db_name(appId, 'Rule'), version, {
    upgrade(db, _oldVersion, _newVersion, _transaction) {
      // Erase all previous data when using a new DB version
      deleteObjectStores(db, [RULE_STORE]);
      /**
       * Rule store contains:
       *  - namespace
       *  - role
       *  - resource
       *  - permission
       *  - expiresAt
       */
      var ruleStore = db.createObjectStore(RULE_STORE, {autoIncrement: true});
      ruleStore.createIndex(
        'compoundIndex',
        ['namespace', 'role', 'resource', 'permission'],
        {
          unique: true,
        },
      );
    },
  });

/**
 *
 * Checks if a specific database exists given its appID, type, and version.
 * It uses the IndexedDB web API to search for the database.
 *
 * @param appId A string representing the APP ID
 * @param dbType The Database type (either "Rule" o "Role")
 * @param version A number representing the Database version
 * @returns A Promise resolving to a boolean indicating whether the database exists (true if it exists, false otherwise).
 */
export async function dbExists(appId: string, dbType: DBType, version: number) {
  const dbName = get_db_name(appId, dbType);
  return !!(await window.indexedDB.databases()).filter(
    db => db.name === dbName && db.version === version,
  ).length;
}

export const fetchAll = async (db: IDBPDatabase, store: StoresType) =>
  await db.transaction(store, 'readonly').objectStore(store).getAll();

const getIDBRange = (store: StoresType, column: string, value: string) => {
  let range = null;
  if (store === ROLE_STORE) {
    if (column === 'address') {
      range = IDBKeyRange.bound([value], [value, []]);
    } else if (column === 'role') {
      range = IDBKeyRange.bound([[], value], [[], value]);
    }
  } else if (store === RULE_STORE) {
    if (column === 'role') {
      range = null;
    } else if (column === 'resource') {
      range = null;
    }
  }
  if (!range) {
    throw new Error(
      `Failed to get IDB Range! Store=${store} -> Column:${column} -> Value="${value}"`,
    );
  }
  return range;
};

export const getFromIndex = async (
  db: IDBPDatabase,
  store: StoresType,
  column: string,
  value: string,
) => {
  const results = await db
    .transaction(store, 'readonly')
    .objectStore(store)
    .index('compoundIndex')
    .getAll(getIDBRange(store, column, value));
  console.log('FETCHED FROM INDEX', results);
  return results;
};

export const getDBConfig = async (db: IDBPDatabase) =>
  await db
    .transaction(CONFIG_STORE, 'readonly')
    .objectStore(CONFIG_STORE)
    .get('Settings');

export const setDBConfig = async (db: IDBPDatabase, newConfig: NewConfigType) =>
  await db
    .transaction(CONFIG_STORE, 'readwrite')
    .objectStore(CONFIG_STORE)
    .put(newConfig, 'Settings');

export const put_role = async (
  appId: string,
  version: number,
  role: RoleType,
) => {
  const db = await getRoleDB(appId, version);
  await db.put(ROLE_STORE, role);
};

export async function bulk_insert(
  db: IDBPDatabase,
  store: 'RuleStore' | 'RoleStore',
  data: (RoleType | RuleType)[],
): Promise<void> {
  return new Promise(async (resolve, reject) => {
    try {
      const transaction = db.transaction(store, 'readwrite');
      const objectStore = transaction.objectStore(store);

      data.forEach(row => {
        objectStore.put(row);
      });

      transaction.oncomplete = () => {
        // console.log(`Bulk insert on "${store}" completed successfully`);
        resolve();
      };

      transaction.onerror = (e: any) => {
        reject(
          new Error(
            `Error performing bulk insert on "${store}":\n${
              e?.target?.error ? e.target.error : ''
            }`,
          ),
        );
      };
    } catch (error) {
      reject(error);
    }
  });
}
