// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

goog.provide('upvote.shared.constants.BlockableState');
goog.provide('upvote.shared.constants.ExemptionState');
goog.provide('upvote.shared.constants.UiBlockableState');
goog.provide('upvote.shared.constants.UserRole');


/**
 * The valid states for a Blockable.
 * These should mirror the values in Upvote's Python shared.constants.State
 * @enum {string}
 * @export
 */
upvote.shared.constants.BlockableState = {
  'UNTRUSTED': 'UNTRUSTED',
  'APPROVED_FOR_LOCAL_WHITELISTING': 'APPROVED_FOR_LOCAL_WHITELISTING',
  'LIMITED': 'LIMITED',
  'GLOBALLY_WHITELISTED': 'GLOBALLY_WHITELISTED',
  'SUSPECT': 'SUSPECT',
  'SILENT_BANNED': 'SILENT_BANNED',
  'BANNED': 'BANNED',
};


/**
 * The Blockable states surfaced to the user.
 * @enum {string}
 * @export
 */
upvote.shared.constants.UiBlockableState = {
  'AWAITING_VOTES': 'AWAITING_VOTES',
  'AVAILABLE': 'AVAILABLE',
  'WHITELISTED': 'WHITELISTED',
  'GLOBALLY_WHITELISTED': 'GLOBALLY_WHITELISTED',
  'FLAGGED': 'FLAGGED',
  'BANNED': 'BANNED',
  'CERT_WHITELISTED': 'CERT_WHITELISTED',
  'CERT_BANNED': 'CERT_BANNED',
};


/**
 * The roles a user can have.
 * @enum {string}
 * @export
 */
upvote.shared.constants.UserRole = {
  'UNTRUSTED_USER': 'UNTRUSTED_USER',
  'USER': 'USER',
  'TRUSTED_USER': 'TRUSTED_USER',
  'SUPERUSER': 'SUPERUSER',
  'SECURITY': 'SECURITY',
  'ADMINISTRATOR': 'ADMINISTRATOR',
};


/**
 * @enum {string}
 * @export
 */
upvote.shared.constants.ExemptionState = {
  'REQUESTED': 'REQUESTED',
  'PENDING': 'PENDING',
  'APPROVED': 'APPROVED',
  'DENIED': 'DENIED',
  'ESCALATED': 'ESCALATED',
  'CANCELLED': 'CANCELLED',
  'REVOKED': 'REVOKED',
  'EXPIRED': 'EXPIRED',
};
