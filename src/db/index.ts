import {IDBPDatabase, openDB} from 'idb';

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

export const get_db_name = (appId: string, type: string): string =>
  `SolCerberus${type}DB_${appId.slice(0, 7)}`;

export const RULE_STORE = 'RuleStore';
export const ROLE_STORE = 'RoleStore';

export const getRoleDB = async (appId: string, version: number) =>
  await openDB(get_db_name(appId, 'Role'), version, {
    upgrade(db, _oldVersion, _newVersion, _transaction) {
      // Erase all previous data when using a new DB version
      if (db.objectStoreNames.contains(ROLE_STORE)) {
        db.deleteObjectStore(ROLE_STORE);
      }
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
      if (db.objectStoreNames.contains(RULE_STORE)) {
        db.deleteObjectStore(RULE_STORE);
      }
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
        ['resource', 'permission', 'role'],
        {
          unique: true,
        },
      );
    },
  });

export const fetchAll = async (db: IDBPDatabase, store: string) =>
  await db.transaction(store, 'readonly').objectStore(store).getAll();

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
        console.log(`Bulk insert on "${store}" completed successfully`);
        resolve();
      };

      transaction.onerror = () => {
        reject(new Error(`Error performing bulk insert on "${store}"`));
      };
    } catch (error) {
      reject(error);
    }
  });
}
