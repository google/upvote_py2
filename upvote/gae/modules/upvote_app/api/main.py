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

"""Main module including WSGI URL mappings for the main Upvote module."""

import webapp2

from webapp2_extras import routes

from upvote.gae.modules.upvote_app.api.handlers import auditlogs
from upvote.gae.modules.upvote_app.api.handlers import blockables
from upvote.gae.modules.upvote_app.api.handlers import constants
from upvote.gae.modules.upvote_app.api.handlers import emergency
from upvote.gae.modules.upvote_app.api.handlers import events
from upvote.gae.modules.upvote_app.api.handlers import export
from upvote.gae.modules.upvote_app.api.handlers import hosts
from upvote.gae.modules.upvote_app.api.handlers import index_handler
from upvote.gae.modules.upvote_app.api.handlers import lookups
from upvote.gae.modules.upvote_app.api.handlers import rules
from upvote.gae.modules.upvote_app.api.handlers import settings
from upvote.gae.modules.upvote_app.api.handlers import users
from upvote.gae.modules.upvote_app.api.handlers import votes
from upvote.gae.shared.common import handlers

_app_route_list = [

    # Warmup
    webapp2.Route(r'/_ah/warmup', handler=handlers.AckHandler),

    # API handlers
    routes.PathPrefixRoute('/api/web', [

        webapp2.Route('/ack', handler=handlers.AckHandler),

        routes.PathPrefixRoute('/auditlogs', [
            webapp2.Route('/query', handler=auditlogs.AuditLogQueryHandler),
            webapp2.Route('/<log_id>', handler=auditlogs.AuditLogHandler),
        ]),

        routes.PathPrefixRoute('/blockables', [
            webapp2.Route(
                '/<blockable_id>/authorized-host-count',
                handler=blockables.AuthorizedHostCountHandler),
            webapp2.Route(
                '/<blockable_id>/unique-event-count',
                handler=blockables.UniqueEventCountHandler),
            webapp2.Route(
                '/<package_id>/contents',
                handler=blockables.PackageContentsHandler),
            webapp2.Route(
                '/<blockable_id>/pending-state-change',
                handler=blockables.PendingStateChangeHandler),
            webapp2.Route(
                '/<blockable_id>/pending-installer-state-change',
                handler=(blockables.PendingInstallerStateChangeHandler)),
            webapp2.Route(
                '/<blockable_id>/installer-state',
                handler=blockables.SetInstallerStateHandler),
            webapp2.Route(
                '/<blockable_id>', handler=blockables.BlockableHandler),
            webapp2.Route(
                '/<platform>/<blockable_type>',
                handler=blockables.BlockableQueryHandler),
        ]),

        routes.PathPrefixRoute('/check', [
            webapp2.Route(
                r'/virustotal/<blockable_id>',
                handler=lookups.Lookup,
                handler_method='check_virus_total'),
        ]),

        webapp2.Route('/constants/<constant>', handler=constants.Constant),

        webapp2.Route('/emergency', handler=emergency.Emergency),

        routes.PathPrefixRoute('/events', [
            webapp2.Route(
                '/most-recent/<blockable_id>',
                handler=events.RecentEventHandler),
            webapp2.Route(
                '/query/bit9', handler=events.Bit9EventQueryHandler),
            webapp2.Route(
                '/query/santa', handler=events.SantaEventQueryHandler),
            webapp2.Route(
                '/query', handler=events.EventQueryHandler),
            webapp2.Route(
                '/<event_key>', handler=events.EventHandler),
        ]),

        routes.PathPrefixRoute('/export', [
            webapp2.Route(
                '/init-bigquery-streaming',
                handler=export.InitializeBigqueryStreaming),
        ]),

        routes.PathPrefixRoute('/hosts', [
            webapp2.Route(
                '/associated/<user_id>',
                handler=hosts.AssociatedHostHandler,
                handler_method='GetByUserId',
                methods=['GET']),
            webapp2.Route(
                '/associated',
                handler=hosts.AssociatedHostHandler,
                handler_method='GetSelf',
                methods=['GET']),
            webapp2.Route('/query/santa', handler=hosts.SantaHostQueryHandler),
            webapp2.Route('/query', handler=hosts.HostQueryHandler),
            webapp2.Route(
                '/<host_id>/event-rate', handler=hosts.HostEventRateHandler),
            webapp2.Route(
                '/<host_id>/request-exception',
                handler=hosts.HostExceptionHandler),
            webapp2.Route(
                '/<host_id>/request-lockdown',
                handler=hosts.LockdownHandler,
                methods=['POST']),
            webapp2.Route('/<host_id>', handler=hosts.HostHandler),
            webapp2.Route(
                '/<host_id>/hidden/<hidden>',
                handler=hosts.VisibilityHandler),
        ]),

        routes.PathPrefixRoute('/rules', [
            webapp2.Route(
                '/query/santa', handler=rules.SantaRuleQueryHandler),
            webapp2.Route('/query', handler=rules.RuleQueryHandler),
            webapp2.Route('/<rule_key>', handler=rules.RuleHandler),
        ]),

        routes.PathPrefixRoute('/settings', [
            webapp2.Route('/api-keys/<key_name>', handler=settings.ApiKeys),
            webapp2.Route('/<setting>', handler=settings.Settings),
        ]),

        routes.PathPrefixRoute('/users', [
            webapp2.Route('/query', handler=users.UserQueryHandler),
            webapp2.Route('/<user_id>', handler=users.UserHandler),
            webapp2.Route('/', handler=users.UserHandler),
            webapp2.Route('', handler=users.UserHandler),
        ]),

        routes.PathPrefixRoute('/votes', [
            webapp2.Route(
                '/cast/<blockable_id>', handler=votes.VoteCastHandler),
            webapp2.Route('/query', handler=votes.VoteQueryHandler),
            webapp2.Route('/<vote_key>', handler=votes.VoteHandler),
        ]),
    ]),

    # Index handler
    webapp2.Route(
        r'/admin<:/?><:.*>',
        handler=index_handler.IndexHandler,
        handler_method='GetAdmin',
        methods=['GET']),

    webapp2.Route(
        r'/<:/?><:.*>',
        handler=index_handler.IndexHandler,
        handler_method='GetUser',
        methods=['GET']),
]

app = webapp2.WSGIApplication(_app_route_list)

handlers.CreateErrorHandlersForApplications([app])
