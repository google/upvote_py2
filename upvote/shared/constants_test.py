# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Lint as: python2, python3
"""Unit tests for constants.py."""

import itertools

from upvote.shared import constants
from absl.testing import absltest


_VOTING_SETS = [
    constants.STATE.SET_VOTING_ALLOWED,
    constants.STATE.SET_VOTING_ALLOWED_ADMIN_ONLY,
    constants.STATE.SET_VOTING_PROHIBITED]


class NamespaceTest(absltest.TestCase):

  def testTuples(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)])
    self.assertEqual(111, namespace.AAA)
    self.assertEqual(222, namespace.BBB)
    self.assertEqual(333, namespace.CCC)
    self.assertSetEqual(set([111, 222, 333]), namespace.SET_ALL)

  def testDefineSet_Invalid(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)])
    self.assertRaises(ValueError, namespace.DefineSet, 'TEST', ['AAA', 'DDD'])

  def testDefineSet_Valid(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)])
    namespace.DefineSet('test', ['AAA', 'CCC'])
    self.assertSetEqual(set([111, 333]), namespace.SET_TEST)

  def testDefineMap(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)])
    namespace.DefineMap('test', {'key1': namespace.AAA, 'key2': namespace.BBB})
    self.assertIn('key1', namespace.MAP_TEST)
    self.assertEqual(111, namespace.MAP_TEST['key1'])
    self.assertIn('key2', namespace.MAP_TEST)
    self.assertEqual(222, namespace.MAP_TEST['key2'])

  def testContains_None(self):

    namespace1 = constants.Namespace(tuples=[('a', None)])
    namespace2 = constants.Namespace(tuples=[('b', 222)])

    for ignore_case in [True, False]:
      self.assertTrue(namespace1.Contains(None, ignore_case=ignore_case))
      self.assertFalse(namespace2.Contains(None, ignore_case=ignore_case))

  def testContains_NonString(self):

    namespace = constants.Namespace(tuples=[('a', 111)])

    for ignore_case in [True, False]:
      self.assertTrue(namespace.Contains(111, ignore_case=ignore_case))
      self.assertFalse(namespace.Contains(222, ignore_case=ignore_case))

  def testContains_String_CaseSensitive(self):

    namespace = constants.Namespace(tuples=[('a', 'aaa')])

    self.assertTrue(namespace.Contains('aaa', ignore_case=False))
    self.assertFalse(namespace.Contains('AAA', ignore_case=False))

  def testContains_String_CaseInsensitive(self):

    namespace = constants.Namespace(tuples=[('a', 'aaa')])

    self.assertTrue(namespace.Contains('aaa', ignore_case=True))
    self.assertTrue(namespace.Contains('AAA', ignore_case=True))

  def testGet_Success(self):

    namespace = constants.Namespace(tuples=[('aaa', 111)])

    self.assertEqual(111, namespace.Get('aaa'))
    self.assertEqual(111, namespace.Get('AAA'))
    self.assertEqual(111, namespace.Get('Aaa'))

  def testGet_InvalidNameError(self):

    namespace = constants.Namespace(tuples=[('aaa', 111)])

    with self.assertRaises(constants.InvalidNameError):
      namespace.Get('bbb')

  def testPrefix(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)], prefix='prefix')
    self.assertEqual('prefix111', namespace.AAA)
    self.assertEqual('prefix222', namespace.BBB)
    self.assertEqual('prefix333', namespace.CCC)
    self.assertSetEqual(
        set(['prefix111', 'prefix222', 'prefix333']), namespace.SET_ALL)

  def testSuffix(self):
    namespace = constants.Namespace(
        tuples=[('aaa', 111), ('bbb', 222), ('ccc', 333)], suffix='suffix')
    self.assertEqual('111suffix', namespace.AAA)
    self.assertEqual('222suffix', namespace.BBB)
    self.assertEqual('333suffix', namespace.CCC)
    self.assertSetEqual(
        set(['111suffix', '222suffix', '333suffix']), namespace.SET_ALL)

  def testValueFromName(self):
    namespace = constants.Namespace(
        names=['aaa', 'bbb', 'ccc'], value_from_name=lambda s: s + '!!!')
    self.assertEqual('aaa!!!', namespace.AAA)
    self.assertEqual('bbb!!!', namespace.BBB)
    self.assertEqual('ccc!!!', namespace.CCC)
    self.assertSetEqual(set(['aaa!!!', 'bbb!!!', 'ccc!!!']), namespace.SET_ALL)

  def testWithoutFunction(self):
    namespace = constants.Namespace(names=['aaa', 'bbb', 'ccc'])
    self.assertEqual('aaa', namespace.AAA)
    self.assertEqual('bbb', namespace.BBB)
    self.assertEqual('ccc', namespace.CCC)
    self.assertSetEqual(set(['aaa', 'bbb', 'ccc']), namespace.SET_ALL)

  def testUppercaseNamespace(self):
    namespace = constants.UppercaseNamespace(['Aa', 'Bb', 'Cc'])
    self.assertEqual('AA', namespace.AA)
    self.assertEqual('BB', namespace.BB)
    self.assertEqual('CC', namespace.CC)
    self.assertSetEqual(set(['AA', 'BB', 'CC']), namespace.SET_ALL)

  def testLowercaseNamespace(self):
    namespace = constants.LowercaseNamespace(['Aa', 'Bb', 'Cc'])
    self.assertEqual('aa', namespace.AA)
    self.assertEqual('bb', namespace.BB)
    self.assertEqual('cc', namespace.CC)
    self.assertSetEqual(set(['aa', 'bb', 'cc']), namespace.SET_ALL)


class ConstantsTest(absltest.TestCase):

  def testVotingSets_Disjoint(self):
    # Ensure that there is no overlap between any of the voting sets.
    for s1, s2 in list(itertools.combinations(_VOTING_SETS, 2)):
      self.assertTrue(s1.isdisjoint(s2))

  def testVotingSets_Cover(self):
    # Ensure that the union of all voting sets is equivalent to SET_ALL.
    union = set().union(*_VOTING_SETS)
    self.assertSetEqual(constants.STATE.SET_ALL, union)

  def testPermissions_EnsureHierarchy(self):

    hierarchy = [
        constants.PERMISSIONS.SET_UNTRUSTED_USER,
        constants.PERMISSIONS.SET_USER,
        constants.PERMISSIONS.SET_TRUSTED_USER,
        constants.PERMISSIONS.SET_SUPERUSER,
        constants.PERMISSIONS.SET_SECURITY,
        constants.PERMISSIONS.SET_ADMINISTRATOR,
        constants.PERMISSIONS.SET_ALL]

    for i in range(1, len(hierarchy)):

      lesser_perms = hierarchy[i - 1]
      greater_perms = hierarchy[i]

      self.assertNotEqual(set(), lesser_perms)
      self.assertNotEqual(set(), greater_perms)
      self.assertGreaterEqual(greater_perms, lesser_perms)


if __name__ == '__main__':
  absltest.main()
