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

"""Views related to Blockables."""
import datetime
import httplib
import logging

import webapp2
from webapp2_extras import routes

from google.appengine.ext import ndb

from upvote.gae.datastore.models import base as base_db
from upvote.gae.datastore.models import bigquery
from upvote.gae.datastore.models import bit9 as bit9_db
from upvote.gae.datastore.models import santa as santa_db
from upvote.gae.modules.bit9_api import change_set
from upvote.gae.modules.upvote_app.api import monitoring
from upvote.gae.modules.upvote_app.api.handlers import base
from upvote.gae.modules.upvote_app.lib import voting
from upvote.gae.shared.common import handlers
from upvote.gae.shared.common import model_mapping
from upvote.gae.shared.common import xsrf_utils
from upvote.shared import constants


class _Platform(object):
  ALL = 'all'
  SANTA = 'santa'
  BIT9 = 'bit9'


class _BlockableType(object):
  ALL = 'all'
  BINARY = 'binaries'
  CERTIFICATE = 'certificates'
  PACKAGE = 'packages'


_MODEL_MAP = {
    _Platform.ALL: {
        _BlockableType.ALL: base_db.Blockable,
        _BlockableType.BINARY: base_db.Binary,
        _BlockableType.CERTIFICATE: base_db.Certificate,
        _BlockableType.PACKAGE: base_db.Package,
    },
    _Platform.SANTA: {
        _BlockableType.ALL: None,
        _BlockableType.BINARY: santa_db.SantaBlockable,
        _BlockableType.CERTIFICATE: santa_db.SantaCertificate,
        _BlockableType.PACKAGE: santa_db.SantaBundle,
    },
    _Platform.BIT9: {
        _BlockableType.ALL: None,
        _BlockableType.BINARY: bit9_db.Bit9Binary,
        _BlockableType.CERTIFICATE: bit9_db.Bit9Certificate,
        _BlockableType.PACKAGE: None,
    }
}


class BlockableQueryHandler(base.BaseQueryHandler):
  """Handlers for querying blockables."""

  # NOTE: Value will be dynamically set but must have a default to
  # satisfy the requirement of the base class.
  MODEL_CLASS = base_db.Blockable
  HAS_INTEGRAL_ID_TYPE = False

  @property
  def RequestCounter(self):
    return monitoring.blockable_requests

  @handlers.RecordRequest
  def get(self, platform, blockable_type):
    normalized_platform = platform.lower()
    normalized_blockable_type = blockable_type.lower()

    # Set the target Model to query against based on the URL arguments.
    platform_map = _MODEL_MAP.get(normalized_platform)
    if not platform_map:
      self.abort(
          httplib.BAD_REQUEST, 'Unknown platform: %s' % normalized_platform)
    elif normalized_blockable_type not in platform_map:
      self.abort(
          httplib.BAD_REQUEST,
          'Unknown Blockable type: %s' % normalized_blockable_type)

    blockable_class = platform_map.get(normalized_blockable_type)
    if not blockable_class:
      self.abort(
          httplib.BAD_REQUEST,
          'Unsupported platform-type pair: %s, %s' % (
              normalized_platform, normalized_blockable_type))

    BlockableQueryHandler.MODEL_CLASS = blockable_class

    # With target Model class set, trigger the query execution.
    self._Query()

  def _QueryModel(self, search_dict):
    if search_dict:
      return super(BlockableQueryHandler, self)._QueryModel(search_dict)
    else:
      return self._ListQuery()

  def _ListQuery(self):
    """Implement a filtering interface with ACLs for blockable queries."""
    query_filter = self.request.get('filter')
    if query_filter == 'flagged':
      logging.debug('Filtering for flagged blockables.')
      query = self._FlaggedBlockablesQuery()
    elif query_filter == 'suspect':
      logging.debug('Filtering for suspect blockables.')
      query = self._SuspectBlockablesQuery()
    elif query_filter == 'own':
      logging.debug('Filtering for own blockables.')
      own_events = base_db.Event.query(ancestor=self.user.key)
      blockable_keys = [e.blockable_key for e in own_events]

      # NOTE: We need to return None here because passing an empty list
      # to self.MODEL_CLASS.key.IN() results in a BadQueryError. See more at
      # http://stackoverflow.com/a/15552890/862857
      if not blockable_keys:
        return
      query = self._BlockablesByKeysQuery(blockable_keys)
    else:
      logging.debug('Returning unfiltered blockable list.')
      query = self._UnfilteredBlockablesQuery()
    return query

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _FlaggedBlockablesQuery(self):
    # pylint: disable=g-explicit-bool-comparison
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.flagged == True
        ).order(-self.MODEL_CLASS.updated_dt)
    # pylint: enable=g-explicit-bool-comparison

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _SuspectBlockablesQuery(self):
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.state == constants.STATE.SUSPECT
        ).order(-self.MODEL_CLASS.updated_dt)

  def _BlockablesByKeysQuery(self, blockable_keys):
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.key.IN(blockable_keys)
        ).order(self.MODEL_CLASS.key)

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _UnfilteredBlockablesQuery(self):
    return self.MODEL_CLASS.query()


class BlockableHandler(base.BaseHandler):
  """Handlers for interacting with individual blockables."""

  def get(self, blockable_id):  # pylint: disable=g-bad-name
    """View of single blockable, accessible to anyone with URL."""
    logging.debug('Blockable handler get method called with ID: %s',
                  blockable_id)
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found')
    self.respond_json(blockable)

  @xsrf_utils.RequireToken
  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def post(self, blockable_id):  # pylint: disable=g-bad-name
    """Post handler for blockables."""
    logging.debug('Blockable handler POST input: %s', self.request.arguments())
    if self.request.get('recount').lower() == 'recount':
      try:
        ballot_box = voting.GetBallotBox(blockable_id)
        ballot_box.Recount()
      except voting.BlockableNotFound:
        self.abort(httplib.NOT_FOUND, explanation='Blockable not found')
      except voting.UnsupportedBlockableType as e:
        self.abort(httplib.BAD_REQUEST, explanation=e.message)
      else:
        self.respond_json(ballot_box.blockable)
    elif self.request.get('reset').lower() == 'reset':
      self._reset_blockable(blockable_id)
    else:
      self._insert_blockable(blockable_id)

  @base.RequireCapability(constants.PERMISSIONS.INSERT_BLOCKABLES)
  def _insert_blockable(self, blockable_id):
    blockable_type = self.request.get('type')
    model_class = getattr(
        model_mapping.BlockableTypeModelMap, blockable_type, None)
    if not model_class:
      self.abort(httplib.BAD_REQUEST, explanation='Model class not found')
    elif model_class.get_by_id(blockable_id):
      self.abort(httplib.CONFLICT, explanation='Blockable already exists')
    else:
      flag = (self.request.get('flagged') == 'true')
      blockable = model_class.get_or_insert(
          blockable_id,
          file_name=self.request.get('fileName'),
          publisher=self.request.get('publisher'),
          flagged=flag,
          id_type=constants.ID_TYPE.SHA256)

      # If one was provided, create a note to accompany the blockable.
      note_text = self.request.get('notes')
      if note_text:
        note_key = base_db.Note.GenerateKey(note_text, blockable.key)
        note = base_db.Note(
            key=note_key, message=note_text, author=self.user.key.id())
        note.put()

        blockable.notes.append(note.key)

      blockable.put()
      self.respond_json(blockable)

  @base.RequireCapability(constants.PERMISSIONS.RESET_BLOCKABLE_STATE)
  def _reset_blockable(self, blockable_id):
    logging.info('Blockable reset: %s', blockable_id)
    try:
      ballot_box = voting.GetBallotBox(blockable_id)
      ballot_box.Reset()
    except voting.BlockableNotFound:
      self.abort(httplib.NOT_FOUND)
    except voting.UnsupportedBlockableType as e:
      self.abort(httplib.BAD_REQUEST, explanation=e.message)
    else:
      self.respond_json(ballot_box.blockable)


class AuthorizedHostCountHandler(base.BaseHandler):
  """Handler for providing the number of hosts able to run a blockable."""

  @base.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')
    elif not isinstance(blockable, santa_db.SantaBlockable):
      self.abort(
          httplib.BAD_REQUEST,
          explanation=(
              'Unsupported Blockable type: %s' % type(blockable).__name__))

    if blockable.state == constants.STATE.GLOBALLY_WHITELISTED:
      self.respond_json(-1)
    else:
      # NOTE: This should really be a projection on SantaRule.host_id
      # but this is not currently supported due to an issue in ndb:
      # https://github.com/GoogleCloudPlatform/datastore-ndb-python/issues/261

      # pylint: disable=g-explicit-bool-comparison
      rule_query = santa_db.SantaRule.query(
          santa_db.SantaRule.policy == constants.RULE_POLICY.WHITELIST,
          santa_db.SantaRule.in_effect == True,
          santa_db.SantaRule.rule_type == blockable.rule_type,
          ancestor=blockable.key)
      # pylint: enable=g-explicit-bool-comparison

      # Fetch used here should be fine as the number of rules returned shouldn't
      # greatly exceed the global whitelist vote threshold (currently 50).
      rules = rule_query.fetch()
      authorized_hosts = {rule.host_id for rule in rules}

      self.respond_json(len(authorized_hosts))


class UniqueEventCountHandler(base.BaseHandler):
  """Handler for providing the number of times a blockable has been blocked."""

  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')
    elif isinstance(blockable, santa_db.SantaBlockable):
      query = santa_db.SantaEvent.query(
          santa_db.SantaEvent.blockable_key == blockable.key)
    elif isinstance(blockable, santa_db.SantaCertificate):
      query = santa_db.SantaEvent.query(
          santa_db.SantaEvent.cert_sha256 == blockable.key.id())
    else:
      self.abort(
          httplib.BAD_REQUEST,
          explanation=(
              'Unsupported Blockable type: %s' % type(blockable).__name__))

    num_events = query.count()

    self.respond_json(num_events)


class PackageContentsHandler(base.BaseHandler):
  """Handler for providing content metadata associated with a package."""

  def get(self, package_id):
    blockable = base_db.Blockable.get_by_id(package_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Package not found.')
    elif not isinstance(blockable, base_db.Package):
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Blockable is not a Package: %s' % blockable)
    elif not isinstance(blockable, santa_db.SantaBundle):
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Only SantaBundles currently supported')

    # Order by the rel_path first, and then by the file_name which should
    # effectively sort by the full relative path in the bundle.
    query = santa_db.SantaBundleBinary.query(ancestor=blockable.key).order(
        santa_db.SantaBundleBinary.rel_path,
        santa_db.SantaBundleBinary.file_name)

    binaries = query.fetch()
    self.respond_json(binaries)


class PendingStateChangeHandler(base.BaseHandler):
  """Determines whether a Bit9 blockable has a pending state change."""

  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')

    platform = blockable.GetPlatformName()
    if platform != constants.PLATFORM.WINDOWS:
      self.respond_json(False)
      return

    # Get uncommitted Rules for this blockable that are relevant to the user.
    # Relevant Rules are either global Rules or local Rules that the user was
    # responsible for creating.
    # pylint: disable=g-explicit-bool-comparison
    pending_rule_query = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.in_effect == True,
        bit9_db.Bit9Rule.is_committed == False,
        bit9_db.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_EXECUTION),
        ndb.OR(
            bit9_db.Bit9Rule.host_id == '',               # Global rule
            bit9_db.Bit9Rule.user_key == self.user.key),  # User's rule
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison
    has_pending_rules = bool(pending_rule_query.count(limit=1))

    self.respond_json(has_pending_rules)


class PendingInstallerStateChangeHandler(base.BaseHandler):
  """Determines whether a Bit9 blockable has a pending state change."""

  def get(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')

    if blockable.GetPlatformName() != constants.PLATFORM.WINDOWS:
      self.respond_json(False)
      return

    # Get any uncommitted installer change Rules for this blockable. Since these
    # are always global, we don't care who initiated the state change action.
    # pylint: disable=g-explicit-bool-comparison
    pending_installer_rule_query = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.in_effect == True,
        bit9_db.Bit9Rule.is_committed == False,
        bit9_db.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_INSTALLER),
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison
    has_pending_rules = bool(pending_installer_rule_query.count(limit=1))

    self.respond_json(has_pending_rules)


class SetInstallerStateHandler(base.BaseHandler):
  """Provides an interface to change a Bit9 blockable's installer state."""

  @ndb.transactional
  def _SetInstallerPolicy(self, blockable_id, new_policy):
    blockable = base_db.Blockable.get_by_id(blockable_id)

    # pylint: disable=g-explicit-bool-comparison
    installer_rule_query = bit9_db.Bit9Rule.query(
        bit9_db.Bit9Rule.in_effect == True,
        bit9_db.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_INSTALLER),
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison
    existing_rule = installer_rule_query.get()
    if existing_rule:
      if existing_rule.policy == new_policy:
        return blockable.is_installer
      else:
        existing_rule.in_effect = False
        existing_rule.put()

    # Create the Bit9Rule associated with the installer state and a change set
    # to commit it.
    new_rule = bit9_db.Bit9Rule(
        rule_type=blockable.rule_type,
        in_effect=True,
        policy=new_policy,
        parent=blockable.key)
    new_rule.put()
    change = bit9_db.RuleChangeSet(
        rule_keys=[new_rule.key],
        change_type=new_rule.policy,
        parent=blockable.key)
    change.put()

    message = 'User %s changed installer state to %s' % (
        self.user.key.id(), new_policy)
    bigquery.BinaryRow.DeferCreate(
        sha256=blockable.key.id(),
        timestamp=datetime.datetime.utcnow(),
        action=constants.BLOCK_ACTION.COMMENT,
        state=blockable.state,
        score=blockable.score,
        platform=constants.PLATFORM.WINDOWS,
        client=constants.CLIENT.BIT9,
        first_seen_file_name=blockable.first_seen_name,
        cert_fingerprint=blockable.cert_id,
        comment=message)

    change_set.DeferCommitBlockableChangeSet(blockable.key)

    # Update the blockable's is_installer property.
    blockable.is_installer = new_policy == constants.RULE_POLICY.FORCE_INSTALLER
    blockable.put()

    return blockable.is_installer

  def post(self, blockable_id):
    blockable = base_db.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')
    elif blockable.GetPlatformName() != constants.PLATFORM.WINDOWS:
      self.abort(httplib.BAD_REQUEST, explanation='Must be a Bit9 blockable')
    elif not isinstance(blockable, base_db.Binary):
      self.abort(httplib.BAD_REQUEST, explanation='Must be a Binary')

    force_installer = self.request.get('value', None)
    if force_installer is None:
      self.abort(httplib.BAD_REQUEST, explanation='No installer state provided')

    new_policy = (
        constants.RULE_POLICY.FORCE_INSTALLER
        if force_installer.lower() == 'true'
        else constants.RULE_POLICY.FORCE_NOT_INSTALLER)

    new_installer_state = self._SetInstallerPolicy(blockable_id, new_policy)
    self.respond_json(new_installer_state)


# The Webapp2 routes defined for these handlers.
ROUTES = routes.PathPrefixRoute('/blockables', [
    webapp2.Route(
        '/<blockable_id>/authorized-host-count',
        handler=AuthorizedHostCountHandler),
    webapp2.Route(
        '/<blockable_id>/unique-event-count',
        handler=UniqueEventCountHandler),
    webapp2.Route(
        '/<package_id>/contents',
        handler=PackageContentsHandler),
    webapp2.Route(
        '/<blockable_id>/pending-state-change',
        handler=PendingStateChangeHandler),
    webapp2.Route(
        '/<blockable_id>/pending-installer-state-change',
        handler=(PendingInstallerStateChangeHandler)),
    webapp2.Route(
        '/<blockable_id>/installer-state',
        handler=SetInstallerStateHandler),
    webapp2.Route(
        '/<blockable_id>',
        handler=BlockableHandler),
    webapp2.Route(
        '/<platform>/<blockable_type>',
        handler=BlockableQueryHandler),
])
