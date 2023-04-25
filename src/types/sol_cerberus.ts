export type SolCerberus = {
  version: '0.1.5';
  name: 'sol_cerberus';
  instructions: [
    {
      name: 'initializeApp';
      accounts: [
        {
          name: 'authority';
          isMut: true;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'arg';
                type: {
                  defined: 'AppData';
                };
                path: 'app_data.id';
              },
            ];
          };
        },
        {
          name: 'systemProgram';
          isMut: false;
          isSigner: false;
        },
      ];
      args: [
        {
          name: 'appData';
          type: {
            defined: 'AppData';
          };
        },
      ];
    },
    {
      name: 'updateAuthority';
      accounts: [
        {
          name: 'signer';
          isMut: false;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
        },
        {
          name: 'systemProgram';
          isMut: false;
          isSigner: false;
        },
      ];
      args: [
        {
          name: 'newAuthority';
          type: 'publicKey';
        },
      ];
    },
    {
      name: 'addRule';
      accounts: [
        {
          name: 'authority';
          isMut: true;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: false;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
          relations: ['authority'];
        },
        {
          name: 'rule';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'arg';
                type: {
                  defined: 'RuleData';
                };
                path: 'rule_data.namespace';
              },
              {
                kind: 'arg';
                type: {
                  defined: 'RuleData';
                };
                path: 'rule_data.role';
              },
              {
                kind: 'arg';
                type: {
                  defined: 'RuleData';
                };
                path: 'rule_data.resource';
              },
              {
                kind: 'arg';
                type: {
                  defined: 'RuleData';
                };
                path: 'rule_data.permission';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
        },
        {
          name: 'systemProgram';
          isMut: false;
          isSigner: false;
        },
      ];
      args: [
        {
          name: 'ruleData';
          type: {
            defined: 'RuleData';
          };
        },
      ];
    },
    {
      name: 'deleteRule';
      accounts: [
        {
          name: 'authority';
          isMut: true;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: false;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
          relations: ['authority'];
        },
        {
          name: 'rule';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'account';
                type: 'u8';
                account: 'Rule';
                path: 'rule.namespace';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'rule.role';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'rule.resource';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'rule.permission';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
        },
        {
          name: 'collector';
          isMut: true;
          isSigner: false;
        },
      ];
      args: [];
    },
    {
      name: 'assignRole';
      accounts: [
        {
          name: 'authority';
          isMut: true;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: false;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
          relations: ['authority'];
        },
        {
          name: 'role';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'arg';
                type: {
                  defined: 'AssignRoleData';
                };
                path: 'assign_role_data.role';
              },
              {
                kind: 'arg';
                type: {
                  defined: 'AssignRoleData';
                };
                path: 'assign_role_data.address';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
        },
        {
          name: 'systemProgram';
          isMut: false;
          isSigner: false;
        },
      ];
      args: [
        {
          name: 'assignRoleData';
          type: {
            defined: 'AssignRoleData';
          };
        },
      ];
    },
    {
      name: 'deleteAssignedRole';
      accounts: [
        {
          name: 'authority';
          isMut: true;
          isSigner: true;
        },
        {
          name: 'app';
          isMut: false;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
          relations: ['authority'];
        },
        {
          name: 'role';
          isMut: true;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'account';
                type: 'string';
                account: 'Role';
                path: 'role.role';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'Role';
                path: 'role.address';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'app.id';
              },
            ];
          };
        },
        {
          name: 'collector';
          isMut: true;
          isSigner: false;
        },
      ];
      args: [];
    },
    {
      name: 'allowed';
      accounts: [
        {
          name: 'signer';
          isMut: false;
          isSigner: true;
        },
        {
          name: 'solCerberusApp';
          isMut: false;
          isSigner: false;
          pda: {
            seeds: [
              {
                kind: 'const';
                type: 'string';
                value: 'app';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'App';
                path: 'sol_cerberus_app.id';
              },
            ];
          };
        },
        {
          name: 'solCerberusRule';
          isMut: false;
          isSigner: false;
          isOptional: true;
          pda: {
            seeds: [
              {
                kind: 'account';
                type: 'u8';
                account: 'Rule';
                path: 'sol_cerberus_rule.namespace';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'sol_cerberus_rule.role';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'sol_cerberus_rule.resource';
              },
              {
                kind: 'account';
                type: 'string';
                account: 'Rule';
                path: 'sol_cerberus_rule.permission';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'Rule';
                path: 'sol_cerberus_rule.app_id';
              },
            ];
          };
        },
        {
          name: 'solCerberusRole';
          isMut: false;
          isSigner: false;
          isOptional: true;
          pda: {
            seeds: [
              {
                kind: 'account';
                type: 'string';
                account: 'Role';
                path: 'sol_cerberus_role.role';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'Role';
                path: 'sol_cerberus_role.address';
              },
              {
                kind: 'account';
                type: 'publicKey';
                account: 'Rule';
                path: 'sol_cerberus_rule';
              },
            ];
          };
        },
        {
          name: 'solCerberusTokenAcc';
          isMut: false;
          isSigner: false;
          isOptional: true;
        },
        {
          name: 'solCerberusMetadata';
          isMut: false;
          isSigner: false;
          isOptional: true;
        },
      ];
      args: [
        {
          name: 'allowedParams';
          type: {
            defined: 'AllowedRule';
          };
        },
      ];
    },
  ];
  accounts: [
    {
      name: 'app';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'id';
            type: 'publicKey';
          },
          {
            name: 'authority';
            type: 'publicKey';
          },
          {
            name: 'recovery';
            type: {
              option: 'publicKey';
            };
          },
          {
            name: 'name';
            type: 'string';
          },
          {
            name: 'bump';
            type: 'u8';
          },
        ];
      };
    },
    {
      name: 'role';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'appId';
            type: 'publicKey';
          },
          {
            name: 'address';
            type: 'publicKey';
          },
          {
            name: 'role';
            type: 'string';
          },
          {
            name: 'addressType';
            type: {
              defined: 'AddressType';
            };
          },
          {
            name: 'createdAt';
            type: 'i64';
          },
          {
            name: 'expiresAt';
            type: {
              option: 'i64';
            };
          },
          {
            name: 'bump';
            type: 'u8';
          },
        ];
      };
    },
    {
      name: 'rule';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'appId';
            type: 'publicKey';
          },
          {
            name: 'namespace';
            type: 'u8';
          },
          {
            name: 'role';
            type: 'string';
          },
          {
            name: 'resource';
            type: 'string';
          },
          {
            name: 'permission';
            type: 'string';
          },
          {
            name: 'createdAt';
            type: 'i64';
          },
          {
            name: 'expiresAt';
            type: {
              option: 'i64';
            };
          },
          {
            name: 'bump';
            type: 'u8';
          },
        ];
      };
    },
  ];
  types: [
    {
      name: 'AllowedRule';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'appId';
            type: 'publicKey';
          },
          {
            name: 'resource';
            type: 'string';
          },
          {
            name: 'permission';
            type: 'string';
          },
        ];
      };
    },
    {
      name: 'AppData';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'id';
            type: 'publicKey';
          },
          {
            name: 'recovery';
            type: {
              option: 'publicKey';
            };
          },
          {
            name: 'name';
            type: 'string';
          },
        ];
      };
    },
    {
      name: 'AssignRoleData';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'address';
            type: 'publicKey';
          },
          {
            name: 'role';
            type: 'string';
          },
          {
            name: 'addressType';
            type: {
              defined: 'AddressType';
            };
          },
          {
            name: 'expiresAt';
            type: {
              option: 'i64';
            };
          },
        ];
      };
    },
    {
      name: 'RuleData';
      type: {
        kind: 'struct';
        fields: [
          {
            name: 'namespace';
            type: 'u8';
          },
          {
            name: 'role';
            type: 'string';
          },
          {
            name: 'resource';
            type: 'string';
          },
          {
            name: 'permission';
            type: 'string';
          },
          {
            name: 'expiresAt';
            type: {
              option: 'i64';
            };
          },
        ];
      };
    },
    {
      name: 'AddressType';
      type: {
        kind: 'enum';
        variants: [
          {
            name: 'Wallet';
          },
          {
            name: 'NFT';
          },
          {
            name: 'Collection';
          },
        ];
      };
    },
  ];
  events: [
    {
      name: 'RolesChanged';
      fields: [
        {
          name: 'time';
          type: 'i64';
          index: false;
        },
        {
          name: 'appId';
          type: 'publicKey';
          index: true;
        },
      ];
    },
    {
      name: 'RulesChanged';
      fields: [
        {
          name: 'time';
          type: 'i64';
          index: false;
        },
        {
          name: 'appId';
          type: 'publicKey';
          index: true;
        },
      ];
    },
  ];
  errors: [
    {
      code: 6000;
      name: 'UnauthorizedAuthorityUpdate';
      msg: 'Only current Authority or Recovery accounts can update the App authority';
    },
    {
      code: 6001;
      name: 'InvalidRule';
      msg: 'Role, Resource or Permission must be betwen 1 and 16 alphanumeric characters long';
    },
    {
      code: 6002;
      name: 'InvalidRole';
      msg: 'Role must be between 1 and 16 alphanumeric characters long';
    },
    {
      code: 6003;
      name: 'StringTooShort';
      msg: 'The provided string is too short';
    },
    {
      code: 6004;
      name: 'StringTooLong';
      msg: 'The provided string is too long';
    },
    {
      code: 6005;
      name: 'Unauthorized';
      msg: 'The user does not have enough privileges to perform this action';
    },
    {
      code: 6006;
      name: 'InvalidAppID';
      msg: 'The Sol Cerberus APP ID does not match the one defined in the program';
    },
    {
      code: 6007;
      name: 'SolCerberusAppIdMissing';
      msg: 'SOL_CERBERUS_APP_ID is missing on lib.rs';
    },
  ];
};

export const IDL: SolCerberus = {
  version: '0.1.5',
  name: 'sol_cerberus',
  instructions: [
    {
      name: 'initializeApp',
      accounts: [
        {
          name: 'authority',
          isMut: true,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'arg',
                type: {
                  defined: 'AppData',
                },
                path: 'app_data.id',
              },
            ],
          },
        },
        {
          name: 'systemProgram',
          isMut: false,
          isSigner: false,
        },
      ],
      args: [
        {
          name: 'appData',
          type: {
            defined: 'AppData',
          },
        },
      ],
    },
    {
      name: 'updateAuthority',
      accounts: [
        {
          name: 'signer',
          isMut: false,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
        },
        {
          name: 'systemProgram',
          isMut: false,
          isSigner: false,
        },
      ],
      args: [
        {
          name: 'newAuthority',
          type: 'publicKey',
        },
      ],
    },
    {
      name: 'addRule',
      accounts: [
        {
          name: 'authority',
          isMut: true,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: false,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
          relations: ['authority'],
        },
        {
          name: 'rule',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'arg',
                type: {
                  defined: 'RuleData',
                },
                path: 'rule_data.namespace',
              },
              {
                kind: 'arg',
                type: {
                  defined: 'RuleData',
                },
                path: 'rule_data.role',
              },
              {
                kind: 'arg',
                type: {
                  defined: 'RuleData',
                },
                path: 'rule_data.resource',
              },
              {
                kind: 'arg',
                type: {
                  defined: 'RuleData',
                },
                path: 'rule_data.permission',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
        },
        {
          name: 'systemProgram',
          isMut: false,
          isSigner: false,
        },
      ],
      args: [
        {
          name: 'ruleData',
          type: {
            defined: 'RuleData',
          },
        },
      ],
    },
    {
      name: 'deleteRule',
      accounts: [
        {
          name: 'authority',
          isMut: true,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: false,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
          relations: ['authority'],
        },
        {
          name: 'rule',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'account',
                type: 'u8',
                account: 'Rule',
                path: 'rule.namespace',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'rule.role',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'rule.resource',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'rule.permission',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
        },
        {
          name: 'collector',
          isMut: true,
          isSigner: false,
        },
      ],
      args: [],
    },
    {
      name: 'assignRole',
      accounts: [
        {
          name: 'authority',
          isMut: true,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: false,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
          relations: ['authority'],
        },
        {
          name: 'role',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'arg',
                type: {
                  defined: 'AssignRoleData',
                },
                path: 'assign_role_data.role',
              },
              {
                kind: 'arg',
                type: {
                  defined: 'AssignRoleData',
                },
                path: 'assign_role_data.address',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
        },
        {
          name: 'systemProgram',
          isMut: false,
          isSigner: false,
        },
      ],
      args: [
        {
          name: 'assignRoleData',
          type: {
            defined: 'AssignRoleData',
          },
        },
      ],
    },
    {
      name: 'deleteAssignedRole',
      accounts: [
        {
          name: 'authority',
          isMut: true,
          isSigner: true,
        },
        {
          name: 'app',
          isMut: false,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
          relations: ['authority'],
        },
        {
          name: 'role',
          isMut: true,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'account',
                type: 'string',
                account: 'Role',
                path: 'role.role',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'Role',
                path: 'role.address',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'app.id',
              },
            ],
          },
        },
        {
          name: 'collector',
          isMut: true,
          isSigner: false,
        },
      ],
      args: [],
    },
    {
      name: 'allowed',
      accounts: [
        {
          name: 'signer',
          isMut: false,
          isSigner: true,
        },
        {
          name: 'solCerberusApp',
          isMut: false,
          isSigner: false,
          pda: {
            seeds: [
              {
                kind: 'const',
                type: 'string',
                value: 'app',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'App',
                path: 'sol_cerberus_app.id',
              },
            ],
          },
        },
        {
          name: 'solCerberusRule',
          isMut: false,
          isSigner: false,
          isOptional: true,
          pda: {
            seeds: [
              {
                kind: 'account',
                type: 'u8',
                account: 'Rule',
                path: 'sol_cerberus_rule.namespace',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'sol_cerberus_rule.role',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'sol_cerberus_rule.resource',
              },
              {
                kind: 'account',
                type: 'string',
                account: 'Rule',
                path: 'sol_cerberus_rule.permission',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'Rule',
                path: 'sol_cerberus_rule.app_id',
              },
            ],
          },
        },
        {
          name: 'solCerberusRole',
          isMut: false,
          isSigner: false,
          isOptional: true,
          pda: {
            seeds: [
              {
                kind: 'account',
                type: 'string',
                account: 'Role',
                path: 'sol_cerberus_role.role',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'Role',
                path: 'sol_cerberus_role.address',
              },
              {
                kind: 'account',
                type: 'publicKey',
                account: 'Rule',
                path: 'sol_cerberus_rule',
              },
            ],
          },
        },
        {
          name: 'solCerberusTokenAcc',
          isMut: false,
          isSigner: false,
          isOptional: true,
        },
        {
          name: 'solCerberusMetadata',
          isMut: false,
          isSigner: false,
          isOptional: true,
        },
      ],
      args: [
        {
          name: 'allowedParams',
          type: {
            defined: 'AllowedRule',
          },
        },
      ],
    },
  ],
  accounts: [
    {
      name: 'app',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'id',
            type: 'publicKey',
          },
          {
            name: 'authority',
            type: 'publicKey',
          },
          {
            name: 'recovery',
            type: {
              option: 'publicKey',
            },
          },
          {
            name: 'name',
            type: 'string',
          },
          {
            name: 'bump',
            type: 'u8',
          },
        ],
      },
    },
    {
      name: 'role',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'appId',
            type: 'publicKey',
          },
          {
            name: 'address',
            type: 'publicKey',
          },
          {
            name: 'role',
            type: 'string',
          },
          {
            name: 'addressType',
            type: {
              defined: 'AddressType',
            },
          },
          {
            name: 'createdAt',
            type: 'i64',
          },
          {
            name: 'expiresAt',
            type: {
              option: 'i64',
            },
          },
          {
            name: 'bump',
            type: 'u8',
          },
        ],
      },
    },
    {
      name: 'rule',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'appId',
            type: 'publicKey',
          },
          {
            name: 'namespace',
            type: 'u8',
          },
          {
            name: 'role',
            type: 'string',
          },
          {
            name: 'resource',
            type: 'string',
          },
          {
            name: 'permission',
            type: 'string',
          },
          {
            name: 'createdAt',
            type: 'i64',
          },
          {
            name: 'expiresAt',
            type: {
              option: 'i64',
            },
          },
          {
            name: 'bump',
            type: 'u8',
          },
        ],
      },
    },
  ],
  types: [
    {
      name: 'AllowedRule',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'appId',
            type: 'publicKey',
          },
          {
            name: 'resource',
            type: 'string',
          },
          {
            name: 'permission',
            type: 'string',
          },
        ],
      },
    },
    {
      name: 'AppData',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'id',
            type: 'publicKey',
          },
          {
            name: 'recovery',
            type: {
              option: 'publicKey',
            },
          },
          {
            name: 'name',
            type: 'string',
          },
        ],
      },
    },
    {
      name: 'AssignRoleData',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'address',
            type: 'publicKey',
          },
          {
            name: 'role',
            type: 'string',
          },
          {
            name: 'addressType',
            type: {
              defined: 'AddressType',
            },
          },
          {
            name: 'expiresAt',
            type: {
              option: 'i64',
            },
          },
        ],
      },
    },
    {
      name: 'RuleData',
      type: {
        kind: 'struct',
        fields: [
          {
            name: 'namespace',
            type: 'u8',
          },
          {
            name: 'role',
            type: 'string',
          },
          {
            name: 'resource',
            type: 'string',
          },
          {
            name: 'permission',
            type: 'string',
          },
          {
            name: 'expiresAt',
            type: {
              option: 'i64',
            },
          },
        ],
      },
    },
    {
      name: 'AddressType',
      type: {
        kind: 'enum',
        variants: [
          {
            name: 'Wallet',
          },
          {
            name: 'NFT',
          },
          {
            name: 'Collection',
          },
        ],
      },
    },
  ],
  events: [
    {
      name: 'RolesChanged',
      fields: [
        {
          name: 'time',
          type: 'i64',
          index: false,
        },
        {
          name: 'appId',
          type: 'publicKey',
          index: true,
        },
      ],
    },
    {
      name: 'RulesChanged',
      fields: [
        {
          name: 'time',
          type: 'i64',
          index: false,
        },
        {
          name: 'appId',
          type: 'publicKey',
          index: true,
        },
      ],
    },
  ],
  errors: [
    {
      code: 6000,
      name: 'UnauthorizedAuthorityUpdate',
      msg: 'Only current Authority or Recovery accounts can update the App authority',
    },
    {
      code: 6001,
      name: 'InvalidRule',
      msg: 'Role, Resource or Permission must be betwen 1 and 16 alphanumeric characters long',
    },
    {
      code: 6002,
      name: 'InvalidRole',
      msg: 'Role must be between 1 and 16 alphanumeric characters long',
    },
    {
      code: 6003,
      name: 'StringTooShort',
      msg: 'The provided string is too short',
    },
    {
      code: 6004,
      name: 'StringTooLong',
      msg: 'The provided string is too long',
    },
    {
      code: 6005,
      name: 'Unauthorized',
      msg: 'The user does not have enough privileges to perform this action',
    },
    {
      code: 6006,
      name: 'InvalidAppID',
      msg: 'The Sol Cerberus APP ID does not match the one defined in the program',
    },
    {
      code: 6007,
      name: 'SolCerberusAppIdMissing',
      msg: 'SOL_CERBERUS_APP_ID is missing on lib.rs',
    },
  ],
};
