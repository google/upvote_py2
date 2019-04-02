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

"""Package-related Datastore models."""

import datetime

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import mixin
from upvote.shared import constants


class Package(base_models.Blockable):

  @property
  def rule_type(self):
    return constants.RULE_TYPE.PACKAGE


class SantaBundleBinary(mixin.Santa, ndb.Model):
  """A binary appearing in a bundle."""
  blockable_key = ndb.KeyProperty()
  rel_path = ndb.StringProperty()
  file_name = ndb.StringProperty()
  cert_key = ndb.KeyProperty()

  @property
  def full_path(self):
    if self.rel_path:
      return '/'.join((self.rel_path, self.file_name))
    else:
      return self.file_name

  @classmethod
  def Generate(cls, bundle_key, blockable_key, **kwargs):
    return cls(
        id=blockable_key.id(), blockable_key=blockable_key, parent=bundle_key,
        **kwargs)

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(
        SantaBundleBinary, self).to_dict(include=include, exclude=exclude)
    result['full_path'] = self.full_path
    result['cert_id'] = self.cert_key.id() if self.cert_key else None
    return result


class SantaBundle(mixin.Santa, Package):
  """A macOS Bundle representing 1 or more SantaBlockables.

  key = the 'bundle hash' defined as the hash of the hashes of all binaries
      contained in the bundle.

  Attributes:
    name: str, CFBundleName. The name of the app ("Google Chrome" for Chrome).
    bundle_id: str, CFBundleIdentifier. The bundle's unique identifier.
    version: str, CFBundleVersion. This is the real 'version' as it's unique
        amongst Bundles of the same name. It's really more of a 'build ID'
        but, hey, the field is called CFBundleVersion so let's just go with it.
    short_version: str, CFBundleShortVersionString. This is the user-facing
        version number which may remain constant across releases.
    has_unsigned_contents: bool, Whether the bundle has binaries that are not
        codesigned.
    binary_count: int, The prescribed number of binaries that should be
        uploaded. This should be set once during upload and once that number of
        binaries have been uploaded, the bundle will be marked as such.
    uploaded_dt: datetime, the time at which the bundle's contents (e.g. the
        binaries and certs that comprise the bundle) were successfully uploaded.
    main_executable_rel_path: str, The path (with filename) of the main
        executable of a bundle.
    main_executable_key: Key, The key to the SantaBundleBinary entity associated
        with the main executable of the bundle (CFBundleExecutable).
        NOTE: This value isn't populated until the SantaBundle has finished
        being uploaded AND if the bundle's executable is not a Mach-O, it will
        never be populated.
    main_cert_key: Key, The key to the cert of the main executable for the
        bundle. This should be identical to main_executable_key.get().cert_key
        but is aliased here to avoid the extra query to get it.
        NOTE: This value isn't populated until the SantaBundle has finished
        being uploaded AND if the bundle's executable is not a Mach-O, it will
        never be populated.
  """

  def _CalculateScore(self):
    # NOTE: This workaround prevents score calculations before the
    # bundle has been uploaded. Voting is disabled on bundles before upload is
    # complete so there shouldn't be any Votes available to count.
    if not self.has_been_uploaded:
      return 0
    return super(SantaBundle, self)._CalculateScore()

  name = ndb.StringProperty()
  bundle_id = ndb.StringProperty()
  version = ndb.StringProperty()
  short_version = ndb.StringProperty()
  has_unsigned_contents = ndb.BooleanProperty(default=False)
  binary_count = ndb.IntegerProperty()
  uploaded_dt = ndb.DateTimeProperty()
  main_executable_rel_path = ndb.StringProperty()
  main_executable_key = ndb.KeyProperty()
  main_cert_key = ndb.KeyProperty()

  # Overrides base.Blockable.score to suppress score calculation during upload.
  score = ndb.ComputedProperty(_CalculateScore)

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'bundle_hash': self.key.id(),
        'timestamp': datetime.datetime.utcnow(),
        'action': action,
        'bundle_id': self.bundle_id,
        'version': self.version,
        'state': self.state,
        'score': self.score}
    defaults.update(kwargs.copy())

    tables.BUNDLE.InsertRow(**defaults)

  @property
  def has_been_uploaded(self):
    return bool(self.uploaded_dt)

  @classmethod
  def TranslatePropertyQuery(cls, field, value):
    if field == 'cert_id':
      if value:
        cert_key = ndb.Key('Certificate', value).urlsafe()
      else:
        cert_key = None
      return 'main_cert_key', cert_key
    return field, value

  @classmethod
  def GetBundleBinaryKeys(cls, bundle_key):
    return SantaBundleBinary.query(ancestor=bundle_key).fetch(keys_only=True)

  @classmethod
  @ndb.tasklet
  def _PageHasFlaggedBinary(cls, page):
    blockables = yield ndb.get_multi_async(
        bundle_binary.blockable_key for bundle_binary in page)
    raise ndb.Return(any(blockable.flagged for blockable in blockables))

  def HasFlaggedBinary(self):
    """Returns whether any of the bundle's blockable contents are flagged."""
    query = SantaBundleBinary.query(ancestor=self.key)
    futures = [
        self._PageHasFlaggedBinary(page)
        for page in datastore_utils.Paginate(query, page_size=1000)]
    return any(future.get_result() for future in futures)

  @classmethod
  @ndb.tasklet
  def _PageHasFlaggedCert(cls, page):
    certs = yield ndb.get_multi_async(
        bundle_binary.cert_key
        for bundle_binary in page
        if bundle_binary.cert_key)
    raise ndb.Return(any(cert.flagged for cert in certs))

  def HasFlaggedCert(self):
    """Returns whether any of the bundle's signing certs are flagged."""
    query = SantaBundleBinary.query(
        projection=[SantaBundleBinary.cert_key], distinct=True,
        ancestor=self.key)
    futures = [
        self._PageHasFlaggedCert(page)
        for page in datastore_utils.Paginate(query, page_size=1000)]
    return any(future.get_result() for future in futures)

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(SantaBundle, self).to_dict(include=include, exclude=exclude)
    result['has_been_uploaded'] = self.has_been_uploaded
    result['cert_id'] = self.main_cert_key.id() if self.main_cert_key else None
    return result
