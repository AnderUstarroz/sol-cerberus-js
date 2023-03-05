import alias from '@rollup/plugin-alias';
import babel from '@rollup/plugin-babel';
import commonjs from '@rollup/plugin-commonjs';
import * as fs from 'fs';
import json from '@rollup/plugin-json';
import path from 'path';
import nodeResolve from '@rollup/plugin-node-resolve';
import copy from 'rollup-plugin-copy';
import replace from '@rollup/plugin-replace';
import {terser} from 'rollup-plugin-terser';

const env = process.env.NODE_ENV;
const extensions = ['.js', '.ts'];

const ignoredDependencies = [
  'crypto-hash',
  'react-native-url-polyfill',
  '@ethersproject/abstract-signer',
  '@ethersproject/abi',
  '@ethersproject/abstract-provider',
  '@ethersproject/address',
  '@ethersproject/base64',
  '@ethersproject/basex',
  '@ethersproject/bignumber',
  '@ethersproject/bytes',
  '@ethersproject/constants',
  '@ethersproject/contracts',
  '@ethersproject/hash',
  '@ethersproject/hdnode',
  '@ethersproject/json-wallets',
  '@ethersproject/keccak256',
  '@ethersproject/logger',
  '@ethersproject/networks',
  '@ethersproject/pbkdf2',
  '@ethersproject/properties',
  '@ethersproject/providers',
  '@ethersproject/random',
  '@ethersproject/rlp',
  '@ethersproject/sha2',
  '@ethersproject/signing-key',
  '@ethersproject/solidity',
  '@ethersproject/strings',
  '@ethersproject/transactions',
  '@ethersproject/units',
  '@ethersproject/wallet',
  '@ethersproject/web',
  '@ethersproject/wordlists',
  '@bundlr-network/client',
  '@project-serum/anchor',
  '@solana-mobile/wallet-adapter-mobile',
  '@solana/wallet-adapter-base',
  '@solana/wallet-adapter-react',
  '@solana/wallet-adapter-react-ui',
  '@solana/wallet-adapter-wallets',
  '@solana/spl-token',
  '@solana/web3.js',
  'big-number',
];

const globals = {
  '@bundlr-network/client': 'client',
  '@solana/web3.js': 'web3_js',
  'filereader-stream': 'fileReaderStream',
  '@project-serum/anchor': 'anchor',
  '@solana/spl-token': 'splToken',
};

function generateConfig(configType, format) {
  const browser = configType === 'browser' || configType === 'react-native';
  const bundle = format === 'iife';

  const config = {
    input: 'src/index.ts',
    plugins: [
      alias({
        entries: [
          {
            find: /^\./, // Relative paths.
            replacement: '.',
            async customResolver(source, importer, options) {
              const resolved = await this.resolve(source, importer, {
                skipSelf: true,
                ...options,
              });
              if (resolved == null) {
                return;
              }
              const {id: resolvedId} = resolved;
              const directory = path.dirname(resolvedId);
              const moduleFilename = path.basename(resolvedId);
              const forkPath = path.join(
                directory,
                '__forks__',
                configType,
                moduleFilename,
              );
              const hasForkCacheKey = `has_fork:${forkPath}`;
              let hasFork = this.cache.get(hasForkCacheKey);
              if (hasFork === undefined) {
                hasFork = fs.existsSync(forkPath);
                this.cache.set(hasForkCacheKey, hasFork);
              }
              if (hasFork) {
                return forkPath;
              }
            },
          },
        ],
      }),
      commonjs(),
      nodeResolve({
        browser,
        dedupe: ['bn.js', 'buffer'],
        extensions,
        preferBuiltins: !browser,
      }),
      babel({
        exclude: '**/node_modules/**',
        extensions,
        babelHelpers: bundle ? 'bundled' : 'runtime',
        plugins: bundle ? [] : ['@babel/plugin-transform-runtime'],
      }),
      replace({
        preventAssignment: true,
        values: {
          'process.env.NODE_ENV': JSON.stringify(env),
          'process.env.BROWSER': JSON.stringify(browser),
          'process.env.npm_package_version': JSON.stringify(
            process.env.npm_package_version,
          ),
        },
      }),
      json({
        exclude: ['node_modules/**'],
        preferConst: true,
        indent: '  ',
      }),
    ],
    onwarn: function (warning, rollupWarn) {
      rollupWarn(warning);
      if (warning.code === 'CIRCULAR_DEPENDENCY') {
        throw new Error(
          'Please eliminate the circular dependencies listed ' +
            'above and retry the build',
        );
      }
    },
    treeshake: {
      moduleSideEffects: false,
    },
  };

  if (!browser) {
    // Prevent dependencies from being bundled
    config.external = ignoredDependencies;
  }

  switch (configType) {
    case 'browser':
    case 'react-native':
      switch (format) {
        case 'iife': {
          config.external = ['http', 'https', 'node-fetch'].concat(
            ignoredDependencies,
          );

          config.output = [
            {
              file: 'lib/index.iife.js',
              format: 'iife',
              name: 'cubistGamesLib',
              sourcemap: true,
              globals: globals,
            },
            {
              file: 'lib/index.iife.min.js',
              format: 'iife',
              name: 'cubistGamesLib',
              sourcemap: true,
              plugins: [terser({mangle: false, compress: false})],
              globals: globals,
            },
          ];

          break;
        }
        default: {
          config.output = [
            {
              file: `lib/index.${
                configType === 'react-native' ? 'native' : 'browser.cjs'
              }.js`,
              format: 'cjs',
              sourcemap: true,
            },
            configType === 'browser'
              ? {
                  file: 'lib/index.browser.esm.js',
                  format: 'es',
                  sourcemap: true,
                }
              : null,
          ].filter(Boolean);

          // Prevent dependencies from being bundled
          config.external = ignoredDependencies;

          break;
        }
      }
      break;
    case 'node':
      config.output = [
        {
          file: 'lib/index.cjs.js',
          format: 'cjs',
          sourcemap: true,
        },
        {
          file: 'lib/index.esm.js',
          format: 'es',
          sourcemap: true,
        },
      ];
      break;
    default:
      throw new Error(`Unknown configType: ${configType}`);
  }
  if (configType === 'node') {
    config.plugins.push(
      copy({
        targets: [
          {
            src: 'src/idl/sol_cerberus.json',
            dest: 'lib/idl',
            rename: 'idl.json',
          },
        ],
      }),
    );
  }

  return config;
}

export default [
  generateConfig('node'),
  generateConfig('browser'),
  generateConfig('browser', 'iife'),
  generateConfig('react-native'),
];
