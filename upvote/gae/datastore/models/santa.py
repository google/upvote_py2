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

"""Models specific to Santa."""

import datetime

from google.appengine.ext import ndb

from upvote.gae.bigquery import tables
from upvote.gae.datastore import utils as datastore_utils
from upvote.gae.datastore.models import base
from upvote.gae.datastore.models import mixin
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import user as user_models
from upvote.shared import constants


class QuarantineMetadata(ndb.Model):
  """Metadata provided by macOS File Quarantine.

  Attributes:
    data_url: str, the URL the file was downloaded from
    referer_url: str, the referer of the above URL
    downloaded_dt: datetime, when the file was downloaded
    agent_bundle_id: str, the program that downloaded the file
  """
  data_url = ndb.StringProperty(indexed=False)
  referer_url = ndb.StringProperty(indexed=False)
  downloaded_dt = ndb.DateTimeProperty()
  agent_bundle_id = ndb.StringProperty()


class SantaEvent(mixin.Santa, base.Event):
  """An event from Santa.

  Attributes:
    bundle_key: ndb.Key, If present, the key of the bundle to which the
        associated Blockable belongs.
    quarantine: QuarantineMetadata, metadata detailing the provenance of the
        Blockable.
    event_type: str, the reason that the last block was generated
    bundle_path: str, path of the associated bundle on the last block.

    DEPRECATED
    cert_sha256: the SHA-256 of the cert this file was signed with
  """
  bundle_key = ndb.KeyProperty()
  quarantine = ndb.StructuredProperty(QuarantineMetadata)
  event_type = ndb.StringProperty(
      choices=constants.EVENT_TYPE.SET_ALL, required=True)
  bundle_path = ndb.StringProperty()

  # DEPRECATED
  cert_sha256 = ndb.StringProperty()

  @property
  def run_by_local_admin(self):
    return self.executing_user == constants.LOCAL_ADMIN.MACOS

  def _DedupeMoreRecentEvent(self, more_recent_event):
    """Updates if the related Event is more recent than the current one."""
    super(SantaEvent, self)._DedupeMoreRecentEvent(more_recent_event)

    self.bundle_path = more_recent_event.bundle_path
    # Keep the newest non-null quarantine information
    if more_recent_event.quarantine:
      self.quarantine = more_recent_event.quarantine

  def _DedupeEarlierEvent(self, earlier_event):
    """Updates if the related Event occurred earlier than the current one."""
    super(SantaEvent, self)._DedupeEarlierEvent(earlier_event)

    # If an older Event has quarantine information and this one does not, pull
    # in the older Event's data
    if not self.quarantine and earlier_event.quarantine:
      self.quarantine = earlier_event.quarantine


class SantaBlockable(mixin.Santa, base.Binary):
  """An binary that has been blocked by Santa.

  key = hash of blockable

  Attributes:
    bundle_id: str, CFBundleIdentifier. The enclosing bundle's unique
        identifier.
    cert_sha256: str, SHA-256 of the codesigning cert, if any.
  """
  bundle_id = ndb.StringProperty()

  # DEPRECATED
  cert_sha256 = ndb.StringProperty()  # Use base.Binary.cert_key

  @property
  def cert_id(self):
    return (self.cert_key and self.cert_key.id()) or self.cert_sha256

  def IsVotingAllowed(self, current_user=None):
    """Method to check if voting is allowed."""
    current_user = current_user or user_models.User.GetOrInsert()

    # Voting is not allowed if the binary is signed by a blacklisted cert if the
    # user is not an admin.
    if not current_user.is_admin and self.cert_id:
      cert = SantaCertificate.get_by_id(self.cert_id)
      # pylint: disable=g-explicit-bool-comparison, singleton-comparison
      cert_rules = rule_models.Rule.query(
          rule_models.Rule.in_effect == True,
          rule_models.Rule.policy == constants.RULE_POLICY.BLACKLIST,
          ancestor=cert.key)
      # pylint: enable=g-explicit-bool-comparison, singleton-comparison
      if cert_rules.count() > 0:
        return (False, constants.VOTING_PROHIBITED_REASONS.BLACKLISTED_CERT)

    return super(self.__class__, self).IsVotingAllowed(
        current_user=current_user)


class SantaCertificate(mixin.Santa, base.Certificate):
  """A certificate used to codesign at least one SantaBlockable.

  key = SHA-256 hash of certificate

  Attributes:
    common_name: str, cert Common Name.
    organization: str, Organization.
    organizational_unit: str, Organizational Unit.
    valid_from_dt: date, datetime that cert is valid from.
    valid_until_dt: date, datetime that cert is valid until.
  """
  common_name = ndb.StringProperty()
  organization = ndb.StringProperty()
  organizational_unit = ndb.StringProperty()
  valid_from_dt = ndb.DateTimeProperty()
  valid_until_dt = ndb.DateTimeProperty()

  def InsertBigQueryRow(self, action, **kwargs):

    defaults = {
        'not_before': self.valid_from_dt,
        'not_after': self.valid_until_dt,
        'common_name': self.common_name,
        'organization': self.organization,
        'organizational_unit': self.organizational_unit}
    defaults.update(kwargs.copy())

    super(SantaCertificate, self).InsertBigQueryRow(action, **defaults)


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


class SantaBundle(mixin.Santa, base.Package):
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
        cert_key = ndb.Key(base.Certificate, value).urlsafe()
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

  def _HasFlaggedBinary(self):
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

  def _HasFlaggedCert(self):
    """Returns whether any of the bundle's signing certs are flagged."""
    query = SantaBundleBinary.query(
        projection=[SantaBundleBinary.cert_key], distinct=True,
        ancestor=self.key)
    futures = [
        self._PageHasFlaggedCert(page)
        for page in datastore_utils.Paginate(query, page_size=1000)]
    return any(future.get_result() for future in futures)

  def IsVotingAllowed(self, current_user=None, enable_flagged_checks=True):
    """Method to check if voting is allowed."""
    # Even admins can't vote on a Bundle that hasn't been uploaded.
    if not self.has_been_uploaded:
      return (False, constants.VOTING_PROHIBITED_REASONS.UPLOADING_BUNDLE)

    current_user = current_user or user_models.User.GetOrInsert()

    # Allow the flagged checks to be suppressed in situations where, for
    # instance, this call must be made from within a transaction.
    if enable_flagged_checks:
      if self._HasFlaggedBinary():
        return (False, constants.VOTING_PROHIBITED_REASONS.FLAGGED_BINARY)
      elif self._HasFlaggedCert():
        return (False, constants.VOTING_PROHIBITED_REASONS.FLAGGED_CERT)

    return super(SantaBundle, self).IsVotingAllowed(current_user=current_user)

  def to_dict(self, include=None, exclude=None):  # pylint: disable=g-bad-name
    result = super(SantaBundle, self).to_dict(include=include, exclude=exclude)
    result['has_been_uploaded'] = self.has_been_uploaded
    result['cert_id'] = self.main_cert_key.id() if self.main_cert_key else None
    return result
