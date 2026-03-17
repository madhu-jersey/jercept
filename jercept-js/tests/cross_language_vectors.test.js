/**
 * Jercept cross-language test vectors.
 * Must stay in sync with tests/test_cross_language_vectors.py in the Python SDK.
 */
import { createScope, permits } from '../src/scope.js';

const VECTORS = [
  ["db.read",           "customer#123", ["db.read"],  [],            ["customer.*"], true ],
  ["db.export",         null,           ["db.*"],     ["db.export"], [],             false],
  ["db.write",          null,           ["db.*"],     [],            [],             true ],
  ["db.read",           "admin#1",      ["db.read"],  [],            ["customer.*"], false],
  ["DB.READ",           null,           ["db.read"],  [],            [],             true ],
  [null,                null,           ["db.read"],  [],            [],             false],
  ["",                  null,           ["db.read"],  [],            [],             false],
  ["   ",               null,           ["db.read"],  [],            [],             false],
  ["db.read;db.export", null,           ["db.read"],  [],            [],             false],
  ["code.execute",      null,           ["db.read"],  [],            [],             false],
  ["db.delete",         "customer#123", ["db.*"],     ["db.delete"], ["customer.*"], false],
  ["db.read",           null,           [],           [],            [],             false],
];

describe('cross-language scope vectors', () => {
  test.each(VECTORS)(
    'permits(%s, %s) → %s',
    (action, resource, allowedActions, deniedActions, allowedResources, expected) => {
      const scope = createScope({ allowedActions, deniedActions, allowedResources });
      expect(permits(scope, action ?? undefined, resource ?? undefined)).toBe(expected);
    }
  );
});
