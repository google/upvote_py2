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

from upvote.gae.bigquery import tables
from upvote.gae.datastore.models import base as base_models
from upvote.gae.datastore.models import bit9 as bit9_models
from upvote.gae.datastore.models import event as event_models
from upvote.gae.datastore.models import note as note_models
from upvote.gae.datastore.models import package as package_models
from upvote.gae.datastore.models import rule as rule_models
from upvote.gae.datastore.models import santa as santa_models
from upvote.gae.lib.bit9 import change_set
from upvote.gae.lib.voting import api as voting_api
from upvote.gae.modules.upvote_app.api.web import monitoring
from upvote.gae.utils import handler_utils
from upvote.gae.utils import xsrf_utils
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
        _BlockableType.ALL: base_models.Blockable,
        _BlockableType.BINARY: base_models.Binary,
        _BlockableType.CERTIFICATE: base_models.Certificate,
        _BlockableType.PACKAGE: package_models.Package,
    },
    _Platform.SANTA: {
        _BlockableType.ALL: None,
        _BlockableType.BINARY: santa_models.SantaBlockable,
        _BlockableType.CERTIFICATE: santa_models.SantaCertificate,
        _BlockableType.PACKAGE: package_models.SantaBundle,
    },
    _Platform.BIT9: {
        _BlockableType.ALL: None,
        _BlockableType.BINARY: bit9_models.Bit9Binary,
        _BlockableType.CERTIFICATE: bit9_models.Bit9Certificate,
        _BlockableType.PACKAGE: None,
    }
}


class BlockableQueryHandler(handler_utils.UserFacingQueryHandler):
  """Handlers for querying blockables."""

  # NOTE: Value will be dynamically set but must have a default to
  # satisfy the requirement of the base class.
  MODEL_CLASS = base_models.Blockable
  HAS_INTEGRAL_ID_TYPE = False

  @property
  def RequestCounter(self):
    return monitoring.blockable_requests

  @handler_utils.RecordRequest
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
      logging.info('Filtering for flagged blockables.')
      query = self._FlaggedBlockablesQuery()
    elif query_filter == 'suspect':
      logging.info('Filtering for suspect blockables.')
      query = self._SuspectBlockablesQuery()
    elif query_filter == 'own':
      logging.info('Filtering for own blockables.')
      own_events = event_models.Event.query(ancestor=self.user.key)
      blockable_keys = [e.blockable_key for e in own_events]

      # NOTE: We need to return None here because passing an empty list
      # to self.MODEL_CLASS.key.IN() results in a BadQueryError. See more at
      # http://stackoverflow.com/a/15552890/862857
      if not blockable_keys:
        return
      query = self._BlockablesByKeysQuery(blockable_keys)
    else:
      logging.info('Returning unfiltered blockable list.')
      query = self._UnfilteredBlockablesQuery()
    return query

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _FlaggedBlockablesQuery(self):
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.flagged == True
        ).order(-self.MODEL_CLASS.updated_dt)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _SuspectBlockablesQuery(self):
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.state == constants.STATE.SUSPECT
        ).order(-self.MODEL_CLASS.updated_dt)

  def _BlockablesByKeysQuery(self, blockable_keys):
    return self.MODEL_CLASS.query(
        self.MODEL_CLASS.key.IN(blockable_keys)
        ).order(self.MODEL_CLASS.key)

  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def _UnfilteredBlockablesQuery(self):
    return self.MODEL_CLASS.query()


class BlockableHandler(handler_utils.UserFacingHandler):
  """Handlers for interacting with individual blockables."""

  def get(self, blockable_id):  # pylint: disable=g-bad-name
    """View of single blockable, accessible to anyone with URL."""
    blockable_id = blockable_id.lower()
    logging.info(
        'Blockable handler get method called with ID: %s', blockable_id)
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found')

    # Augment the response dict with related voting data.
    blockable_dict = blockable.to_dict()
    allowed, reason = voting_api.IsVotingAllowed(blockable.key)
    blockable_dict['is_voting_allowed'] = allowed
    blockable_dict['voting_prohibited_reason'] = reason

    self.respond_json(blockable_dict)

  @xsrf_utils.RequireToken
  @handler_utils.RequireCapability(constants.PERMISSIONS.VIEW_OTHER_BLOCKABLES)
  def post(self, blockable_id):  # pylint: disable=g-bad-name
    """Post handler for blockables."""
    blockable_id = blockable_id.lower()
    logging.info('Blockable handler POST input: %s', self.request.arguments())
    if self.request.get('recount').lower() == 'recount':
      try:
        voting_api.Recount(blockable_id)
      except voting_api.BlockableNotFoundError:
        self.abort(httplib.NOT_FOUND, explanation='Blockable not found')
      except voting_api.UnsupportedClientError:
        self.abort(httplib.BAD_REQUEST, explanation='Unsupported client')
      except Exception as e:  # pylint: disable=broad-except
        self.abort(httplib.INTERNAL_SERVER_ERROR, explanation=e.message)
      else:
        blockable = base_models.Blockable.get_by_id(blockable_id)
        self.respond_json(blockable)
    elif self.request.get('reset').lower() == 'reset':
      self._reset_blockable(blockable_id)
    else:
      self._insert_blockable(blockable_id, datetime.datetime.utcnow())

  @ndb.transactional(xg=True)  # xg because respond_json() touches User.
  @handler_utils.RequireCapability(constants.PERMISSIONS.INSERT_BLOCKABLES)
  def _insert_blockable(self, blockable_id, timestamp):

    blockable_type = self.request.get('type')

    model_class_map = {
        constants.BLOCKABLE_TYPE.SANTA_BINARY:
            santa_models.SantaBlockable,
        constants.BLOCKABLE_TYPE.SANTA_CERTIFICATE:
            santa_models.SantaCertificate}
    model_class = model_class_map.get(blockable_type, None)

    if not model_class:
      self.abort(
          httplib.BAD_REQUEST,
          explanation='No Model class found for "%s"' % blockable_type)

    elif model_class.get_by_id(blockable_id):
      self.abort(
          httplib.CONFLICT,
          explanation='Blockable "%s" already exists' % blockable_id)

    else:
      flag = (self.request.get('flagged') == 'true')

      logging.info('Creating new %s %s', model_class.__name__, blockable_id)
      blockable = model_class.get_or_insert(
          blockable_id,
          file_name=self.request.get('fileName'),
          publisher=self.request.get('publisher'),
          flagged=flag,
          id_type=constants.ID_TYPE.SHA256)
      blockable.InsertBigQueryRow(
          constants.BLOCK_ACTION.FIRST_SEEN, timestamp=timestamp)

      # If one was provided, create a note to accompany the blockable.
      note_text = self.request.get('notes')
      if note_text:
        note_key = note_models.Note.GenerateKey(note_text, blockable.key)
        note = note_models.Note(
            key=note_key, message=note_text, author=self.user.key.id())
        note.put()

        blockable.notes.append(note.key)

      blockable.put()
      self.respond_json(blockable)

  @handler_utils.RequireCapability(constants.PERMISSIONS.RESET_BLOCKABLE_STATE)
  def _reset_blockable(self, blockable_id):
    logging.info('Blockable reset: %s', blockable_id)
    try:
      voting_api.Reset(blockable_id)
    except voting_api.BlockableNotFoundError:
      self.abort(httplib.NOT_FOUND)
    except voting_api.UnsupportedClientError:
      self.abort(httplib.BAD_REQUEST, explanation='Unsupported client')
    except voting_api.OperationNotAllowedError as e:
      self.abort(httplib.FORBIDDEN, explanation=e.message)
    except Exception as e:  # pylint: disable=broad-except
      self.abort(httplib.INTERNAL_SERVER_ERROR, explanation=e.message)
    else:
      blockable = base_models.Blockable.get_by_id(blockable_id)
      self.respond_json(blockable)


class PackageContentsHandler(handler_utils.UserFacingHandler):
  """Handler for providing content metadata associated with a package."""

  def get(self, package_id):
    blockable = base_models.Blockable.get_by_id(package_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Package not found.')
    elif not isinstance(blockable, package_models.Package):
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Blockable is not a Package: %s' % blockable)
    elif not isinstance(blockable, package_models.SantaBundle):
      self.abort(
          httplib.BAD_REQUEST,
          explanation='Only SantaBundles currently supported')

    # Order by the rel_path first, and then by the file_name which should
    # effectively sort by the full relative path in the bundle.
    query = package_models.SantaBundleBinary.query(
        ancestor=blockable.key).order(
            package_models.SantaBundleBinary.rel_path,
            package_models.SantaBundleBinary.file_name)

    binaries = query.fetch()
    self.respond_json(binaries)


class PendingStateChangeHandler(handler_utils.UserFacingHandler):
  """Determines whether a Bit9 blockable has a pending state change."""

  def get(self, blockable_id):
    blockable_id = blockable_id.lower()
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')

    platform = blockable.GetPlatformName()
    if platform != constants.PLATFORM.WINDOWS:
      self.respond_json(False)
      return

    # Get uncommitted Rules for this blockable that are relevant to the user.
    # Relevant Rules are either global Rules or local Rules that the user was
    # responsible for creating.
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    pending_rule_query = rule_models.Bit9Rule.query(
        rule_models.Bit9Rule.in_effect == True,
        rule_models.Bit9Rule.is_committed == False,
        rule_models.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_EXECUTION),
        ndb.OR(
            rule_models.Bit9Rule.host_id == '',               # Global rule
            rule_models.Bit9Rule.user_key == self.user.key),  # User's rule
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    has_pending_rules = bool(pending_rule_query.count(limit=1))

    self.respond_json(has_pending_rules)


class PendingInstallerStateChangeHandler(handler_utils.UserFacingHandler):
  """Determines whether a Bit9 blockable has a pending state change."""

  def get(self, blockable_id):
    blockable_id = blockable_id.lower()
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')

    if blockable.GetPlatformName() != constants.PLATFORM.WINDOWS:
      self.respond_json(False)
      return

    # Get any uncommitted installer change Rules for this blockable. Since these
    # are always global, we don't care who initiated the state change action.
    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    pending_installer_rule_query = rule_models.Bit9Rule.query(
        rule_models.Bit9Rule.in_effect == True,
        rule_models.Bit9Rule.is_committed == False,
        rule_models.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_INSTALLER),
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    has_pending_rules = bool(pending_installer_rule_query.count(limit=1))

    self.respond_json(has_pending_rules)


class SetInstallerStateHandler(handler_utils.UserFacingHandler):
  """Provides an interface to change a Bit9 blockable's installer state."""

  @ndb.transactional
  def _SetInstallerPolicy(self, blockable_id, new_policy):
    blockable = base_models.Blockable.get_by_id(blockable_id)

    # pylint: disable=g-explicit-bool-comparison, singleton-comparison
    installer_rule_query = rule_models.Bit9Rule.query(
        rule_models.Bit9Rule.in_effect == True,
        rule_models.Bit9Rule.policy.IN(constants.RULE_POLICY.SET_INSTALLER),
        ancestor=blockable.key)
    # pylint: enable=g-explicit-bool-comparison, singleton-comparison
    existing_rule = installer_rule_query.get()
    if existing_rule:
      if existing_rule.policy == new_policy:
        return blockable.is_installer
      else:
        existing_rule.in_effect = False
        existing_rule.put()

    # Create the Bit9Rule associated with the installer state and a change set
    # to commit it.
    new_rule = rule_models.Bit9Rule(
        rule_type=blockable.rule_type,
        in_effect=True,
        policy=new_policy,
        parent=blockable.key)
    new_rule.put()
    change = rule_models.RuleChangeSet(
        rule_keys=[new_rule.key],
        change_type=new_rule.policy,
        parent=blockable.key)
    change.put()

    message = 'User %s changed installer state to %s' % (
        self.user.key.id(), new_policy)
    tables.BINARY.InsertRow(
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
    blockable_id = blockable_id.lower()
    blockable = base_models.Blockable.get_by_id(blockable_id)
    if not blockable:
      self.abort(httplib.NOT_FOUND, explanation='Blockable not found.')
    elif blockable.GetPlatformName() != constants.PLATFORM.WINDOWS:
      self.abort(httplib.BAD_REQUEST, explanation='Must be a Bit9 blockable')
    elif not isinstance(blockable, base_models.Binary):
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
