import {IDBPDatabase, openDB} from 'idb';
import {PublicKey} from '@solana/web3.js';

export interface RoleType {
  id: string;
  role: string;
  address: PublicKey;
  addressType: 'wallet' | 'nft' | 'collection';
  expiresAt: number;
}
export interface RuleType {
  id: string;
  namespace: number;
  role: string;
  resource: string;
  permission: string;
  expiresAt: number;
}

export const get_db_name = (appId: string): string =>
  `SolCerberusDB_${appId.slice(0, 7)}`;

export const RULE_STORE = 'RuleStore';
export const ROLE_STORE = 'RoleStore';

export const getDB = async (appId: string, version: number) => {
  return await openDB(get_db_name(appId), version, {
    upgrade(db, _oldVersion, _newVersion, _transaction) {
      // Erase all previous data when using a new DB version
      for (const store of [ROLE_STORE, RULE_STORE]) {
        if (db.objectStoreNames.contains(store)) {
          db.deleteObjectStore(store);
          console.debug(`Deleted store: ${store} v${_oldVersion}`);
        }
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
      /**
       * Rule store contains:
       *  - namespace
       *  - role
       *  - resource
       *  - permission
       *  - createdAt
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
};

export const get_all_rules = async (db: IDBPDatabase) => {
  const tx = db.transaction(RULE_STORE, 'readonly');
  const store = tx.objectStore(RULE_STORE);
  return await store.getAll();
};

export const put_role = async (
  appId: string,
  version: number,
  role: RoleType,
) => {
  const db = await getDB(appId, version);
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
        console.log('Bulk insert completed successfully.');
        resolve();
      };

      transaction.onerror = () => {
        reject(new Error('Error performing bulk insert.'));
      };
    } catch (error) {
      reject(error);
    }
  });
}
