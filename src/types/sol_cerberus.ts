export type SolCerberus = {
  "version": "0.1.12",
  "name": "sol_cerberus",
  "instructions": [
    {
      "name": "initializeApp",
      "accounts": [
        {
          "name": "authority",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "AppData"
                },
                "path": "app_data.id"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "appData",
          "type": {
            "defined": "AppData"
          }
        }
      ]
    },
    {
      "name": "updateApp",
      "accounts": [
        {
          "name": "signer",
          "isMut": false,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "appData",
          "type": {
            "defined": "UpdateAppData"
          }
        }
      ]
    },
    {
      "name": "deleteApp",
      "accounts": [
        {
          "name": "authority",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "addRule",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "rule",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.namespace"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.role"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.resource"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule2",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule2.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule2.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "ruleData",
          "type": {
            "defined": "RuleData"
          }
        }
      ]
    },
    {
      "name": "deleteRule",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "rule",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule2",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule2.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule2.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "assignRole",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "role",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "assignRoleData",
          "type": {
            "defined": "AssignRoleData"
          }
        }
      ]
    },
    {
      "name": "deleteAssignedRole",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "role",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "updateCache",
      "docs": [
        "* Updates either app.roles_updated_at or app.rules_updated_at fields, so clients\n     * can keep track and cache roles & rules accordingly."
      ],
      "accounts": [
        {
          "name": "authority",
          "isMut": false,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          },
          "relations": [
            "authority"
          ]
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "cacheUpdated",
          "type": "u8"
        }
      ]
    },
    {
      "name": "allowed",
      "docs": [
        "* Checks if the current user is authorized to run the instruction,\n     * throwing \"Unauthorized\" error otherwise."
      ],
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "allowedRule",
          "type": {
            "defined": "AllowedRule"
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "app",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "publicKey"
          },
          {
            "name": "authority",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "rolesUpdatedAt",
            "type": "i64"
          },
          {
            "name": "rulesUpdatedAt",
            "type": "i64"
          },
          {
            "name": "cached",
            "type": "bool"
          },
          {
            "name": "fee",
            "type": {
              "option": "u64"
            }
          },
          {
            "name": "accountType",
            "type": "u8"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "seed",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "initialized",
            "type": "bool"
          }
        ]
      }
    },
    {
      "name": "role",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "address",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "addressType",
            "type": {
              "defined": "AddressType"
            }
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "rule",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    }
  ],
  "types": [
    {
      "name": "AllowedRule",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          }
        ]
      }
    },
    {
      "name": "AppData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "cached",
            "type": "bool"
          }
        ]
      }
    },
    {
      "name": "UpdateAppData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "cached",
            "type": "bool"
          },
          {
            "name": "fee",
            "type": {
              "option": "u64"
            }
          },
          {
            "name": "accountType",
            "type": "u8"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "AssignRoleData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "address",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "addressType",
            "type": {
              "defined": "AddressType"
            }
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "RuleData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "AccountTypes",
      "docs": [
        "AccountTypes:",
        "0 => Basic  (Apps with default fees)",
        "1 => Free   (Apps with no fees)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Basic"
          },
          {
            "name": "Free"
          }
        ]
      }
    },
    {
      "name": "CacheUpdated",
      "docs": [
        "CacheUpdated:",
        "0 => Roles (When roles change)",
        "1 => Rules   (When rules change)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Roles"
          },
          {
            "name": "Rules"
          }
        ]
      }
    },
    {
      "name": "AddressType",
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Wallet"
          },
          {
            "name": "Nft"
          },
          {
            "name": "Collection"
          }
        ]
      }
    },
    {
      "name": "Namespaces",
      "docs": [
        "Namespaces:",
        "0 => Rule (Normal permissions)",
        "1 => AssignRole (White list of roles that can be assigned by certain role)",
        "2 => DeleteAssignRole (White list of roles that can be deleted by certain role)",
        "3 => AddRuleNSRole (White list of namespaces and roles that can be created by certain role)",
        "4 => AddRuleResourcePerm (White list of resources and permissions that can be created by certain role)",
        "5 => DeleteRuleNSRole (White list of namespaces and roles that can be deleted by certain role)",
        "6 => DeleteRuleResourcePerm (White list of resources and permissions that can be deleted by certain role)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Rule"
          },
          {
            "name": "AssignRole"
          },
          {
            "name": "DeleteAssignRole"
          },
          {
            "name": "AddRuleNSRole"
          },
          {
            "name": "AddRuleResourcePerm"
          },
          {
            "name": "DeleteRuleNSRole"
          },
          {
            "name": "DeleteRuleResourcePerm"
          }
        ]
      }
    }
  ],
  "events": [
    {
      "name": "AppChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        },
        {
          "name": "authority",
          "type": "publicKey",
          "index": false
        }
      ]
    },
    {
      "name": "RolesChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        }
      ]
    },
    {
      "name": "RulesChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        }
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "UnauthorizedAuthorityUpdate",
      "msg": "Only current Authority or Recovery accounts can update the App authority"
    },
    {
      "code": 6001,
      "name": "InvalidRule",
      "msg": "Role, Resource or Permission must be betwen 1 and 16 alphanumeric characters long"
    },
    {
      "code": 6002,
      "name": "InvalidRole",
      "msg": "Role must be between 1 and 16 alphanumeric characters long"
    },
    {
      "code": 6003,
      "name": "StringTooShort",
      "msg": "The provided string is too short"
    },
    {
      "code": 6004,
      "name": "StringTooLong",
      "msg": "The provided string is too long"
    },
    {
      "code": 6005,
      "name": "Unauthorized",
      "msg": "The user does not have enough privileges to perform this action"
    },
    {
      "code": 6006,
      "name": "InvalidAppID",
      "msg": "The Sol Cerberus APP ID does not match the one defined in the program"
    },
    {
      "code": 6007,
      "name": "InvalidAddressType",
      "msg": "Invalid address type, mus be either 'Wallet', 'Nft', 'Collection' or a wildcard '*'"
    },
    {
      "code": 6008,
      "name": "InvalidNamespace",
      "msg": "Invalid namespace, must be either an u8 number (0-255) or a wildcard '*'"
    },
    {
      "code": 6009,
      "name": "MissingSolCerberusAppId",
      "msg": "SOL_CERBERUS_APP_ID is missing on lib.rs"
    },
    {
      "code": 6010,
      "name": "MissingSeedAccount",
      "msg": "The Sol Cerberus Seed account is missing"
    },
    {
      "code": 6011,
      "name": "UnauthorizedProgramAuthority",
      "msg": "Only program authority can perform this action"
    },
    {
      "code": 6012,
      "name": "InsufficientFunds",
      "msg": "Insufficient funds for transaction"
    }
  ]
};

export const IDL: SolCerberus = {
  "version": "0.1.12",
  "name": "sol_cerberus",
  "instructions": [
    {
      "name": "initializeApp",
      "accounts": [
        {
          "name": "authority",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "AppData"
                },
                "path": "app_data.id"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "appData",
          "type": {
            "defined": "AppData"
          }
        }
      ]
    },
    {
      "name": "updateApp",
      "accounts": [
        {
          "name": "signer",
          "isMut": false,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "appData",
          "type": {
            "defined": "UpdateAppData"
          }
        }
      ]
    },
    {
      "name": "deleteApp",
      "accounts": [
        {
          "name": "authority",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "addRule",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "rule",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.namespace"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.role"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.resource"
              },
              {
                "kind": "arg",
                "type": {
                  "defined": "RuleData"
                },
                "path": "rule_data.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule2",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule2.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule2.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "ruleData",
          "type": {
            "defined": "RuleData"
          }
        }
      ]
    },
    {
      "name": "deleteRule",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "rule",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule2",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule2.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule2.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule2.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "assignRole",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "role",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "assignRoleData",
          "type": {
            "defined": "AssignRoleData"
          }
        }
      ]
    },
    {
      "name": "deleteAssignedRole",
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "role",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "collector",
          "isMut": true,
          "isSigner": false
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": []
    },
    {
      "name": "updateCache",
      "docs": [
        "* Updates either app.roles_updated_at or app.rules_updated_at fields, so clients\n     * can keep track and cache roles & rules accordingly."
      ],
      "accounts": [
        {
          "name": "authority",
          "isMut": false,
          "isSigner": true
        },
        {
          "name": "app",
          "isMut": true,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "app.id"
              }
            ]
          },
          "relations": [
            "authority"
          ]
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "cacheUpdated",
          "type": "u8"
        }
      ]
    },
    {
      "name": "allowed",
      "docs": [
        "* Checks if the current user is authorized to run the instruction,\n     * throwing \"Unauthorized\" error otherwise."
      ],
      "accounts": [
        {
          "name": "signer",
          "isMut": true,
          "isSigner": true
        },
        {
          "name": "solCerberusApp",
          "isMut": false,
          "isSigner": false,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "app"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "App",
                "path": "sol_cerberus_app.id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRule",
          "isMut": false,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "account",
                "type": "u8",
                "account": "Rule",
                "path": "sol_cerberus_rule.namespace"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.role"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.resource"
              },
              {
                "kind": "account",
                "type": "string",
                "account": "Rule",
                "path": "sol_cerberus_rule.permission"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "account": "Rule",
                "path": "sol_cerberus_rule.app_id"
              }
            ]
          }
        },
        {
          "name": "solCerberusRole",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusToken",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusMetadata",
          "isMut": false,
          "isSigner": false,
          "isOptional": true
        },
        {
          "name": "solCerberusSeed",
          "isMut": true,
          "isSigner": false,
          "isOptional": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "type": "string",
                "value": "seed"
              },
              {
                "kind": "account",
                "type": "publicKey",
                "path": "signer"
              }
            ]
          }
        },
        {
          "name": "systemProgram",
          "isMut": false,
          "isSigner": false
        }
      ],
      "args": [
        {
          "name": "allowedRule",
          "type": {
            "defined": "AllowedRule"
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "app",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "publicKey"
          },
          {
            "name": "authority",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "rolesUpdatedAt",
            "type": "i64"
          },
          {
            "name": "rulesUpdatedAt",
            "type": "i64"
          },
          {
            "name": "cached",
            "type": "bool"
          },
          {
            "name": "fee",
            "type": {
              "option": "u64"
            }
          },
          {
            "name": "accountType",
            "type": "u8"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "seed",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "initialized",
            "type": "bool"
          }
        ]
      }
    },
    {
      "name": "role",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "address",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "addressType",
            "type": {
              "defined": "AddressType"
            }
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "rule",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    }
  ],
  "types": [
    {
      "name": "AllowedRule",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "appId",
            "type": "publicKey"
          },
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          }
        ]
      }
    },
    {
      "name": "AppData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "cached",
            "type": "bool"
          }
        ]
      }
    },
    {
      "name": "UpdateAppData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "authority",
            "type": "publicKey"
          },
          {
            "name": "recovery",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "cached",
            "type": "bool"
          },
          {
            "name": "fee",
            "type": {
              "option": "u64"
            }
          },
          {
            "name": "accountType",
            "type": "u8"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "AssignRoleData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "address",
            "type": {
              "option": "publicKey"
            }
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "addressType",
            "type": {
              "defined": "AddressType"
            }
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "RuleData",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "namespace",
            "type": "u8"
          },
          {
            "name": "role",
            "type": "string"
          },
          {
            "name": "resource",
            "type": "string"
          },
          {
            "name": "permission",
            "type": "string"
          },
          {
            "name": "expiresAt",
            "type": {
              "option": "i64"
            }
          }
        ]
      }
    },
    {
      "name": "AccountTypes",
      "docs": [
        "AccountTypes:",
        "0 => Basic  (Apps with default fees)",
        "1 => Free   (Apps with no fees)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Basic"
          },
          {
            "name": "Free"
          }
        ]
      }
    },
    {
      "name": "CacheUpdated",
      "docs": [
        "CacheUpdated:",
        "0 => Roles (When roles change)",
        "1 => Rules   (When rules change)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Roles"
          },
          {
            "name": "Rules"
          }
        ]
      }
    },
    {
      "name": "AddressType",
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Wallet"
          },
          {
            "name": "Nft"
          },
          {
            "name": "Collection"
          }
        ]
      }
    },
    {
      "name": "Namespaces",
      "docs": [
        "Namespaces:",
        "0 => Rule (Normal permissions)",
        "1 => AssignRole (White list of roles that can be assigned by certain role)",
        "2 => DeleteAssignRole (White list of roles that can be deleted by certain role)",
        "3 => AddRuleNSRole (White list of namespaces and roles that can be created by certain role)",
        "4 => AddRuleResourcePerm (White list of resources and permissions that can be created by certain role)",
        "5 => DeleteRuleNSRole (White list of namespaces and roles that can be deleted by certain role)",
        "6 => DeleteRuleResourcePerm (White list of resources and permissions that can be deleted by certain role)"
      ],
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "Rule"
          },
          {
            "name": "AssignRole"
          },
          {
            "name": "DeleteAssignRole"
          },
          {
            "name": "AddRuleNSRole"
          },
          {
            "name": "AddRuleResourcePerm"
          },
          {
            "name": "DeleteRuleNSRole"
          },
          {
            "name": "DeleteRuleResourcePerm"
          }
        ]
      }
    }
  ],
  "events": [
    {
      "name": "AppChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        },
        {
          "name": "authority",
          "type": "publicKey",
          "index": false
        }
      ]
    },
    {
      "name": "RolesChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        }
      ]
    },
    {
      "name": "RulesChanged",
      "fields": [
        {
          "name": "time",
          "type": "i64",
          "index": false
        },
        {
          "name": "appId",
          "type": "publicKey",
          "index": true
        }
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "UnauthorizedAuthorityUpdate",
      "msg": "Only current Authority or Recovery accounts can update the App authority"
    },
    {
      "code": 6001,
      "name": "InvalidRule",
      "msg": "Role, Resource or Permission must be betwen 1 and 16 alphanumeric characters long"
    },
    {
      "code": 6002,
      "name": "InvalidRole",
      "msg": "Role must be between 1 and 16 alphanumeric characters long"
    },
    {
      "code": 6003,
      "name": "StringTooShort",
      "msg": "The provided string is too short"
    },
    {
      "code": 6004,
      "name": "StringTooLong",
      "msg": "The provided string is too long"
    },
    {
      "code": 6005,
      "name": "Unauthorized",
      "msg": "The user does not have enough privileges to perform this action"
    },
    {
      "code": 6006,
      "name": "InvalidAppID",
      "msg": "The Sol Cerberus APP ID does not match the one defined in the program"
    },
    {
      "code": 6007,
      "name": "InvalidAddressType",
      "msg": "Invalid address type, mus be either 'Wallet', 'Nft', 'Collection' or a wildcard '*'"
    },
    {
      "code": 6008,
      "name": "InvalidNamespace",
      "msg": "Invalid namespace, must be either an u8 number (0-255) or a wildcard '*'"
    },
    {
      "code": 6009,
      "name": "MissingSolCerberusAppId",
      "msg": "SOL_CERBERUS_APP_ID is missing on lib.rs"
    },
    {
      "code": 6010,
      "name": "MissingSeedAccount",
      "msg": "The Sol Cerberus Seed account is missing"
    },
    {
      "code": 6011,
      "name": "UnauthorizedProgramAuthority",
      "msg": "Only program authority can perform this action"
    },
    {
      "code": 6012,
      "name": "InsufficientFunds",
      "msg": "Insufficient funds for transaction"
    }
  ]
};
