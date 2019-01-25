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

/**
 * @fileoverview These types should parallel the Upvote data models
 * (found at upvote/gae/shared/models) with the addition of
 * fields added during serialization ('class_' and 'operatingSystemFamily').
 */
goog.provide('upvote.shared.models.AnyBlockable');
goog.provide('upvote.shared.models.AnyEvent');
goog.provide('upvote.shared.models.AnyHost');
goog.provide('upvote.shared.models.Bit9Binary');
goog.provide('upvote.shared.models.Bit9Event');
goog.provide('upvote.shared.models.Host');
goog.provide('upvote.shared.models.QuarantineMetadata');
goog.provide('upvote.shared.models.SantaBlockable');
goog.provide('upvote.shared.models.SantaBundle');
goog.provide('upvote.shared.models.SantaBundleBinary');
goog.provide('upvote.shared.models.SantaCertificate');
goog.provide('upvote.shared.models.SantaEvent');
goog.provide('upvote.shared.models.SantaHost');
goog.provide('upvote.shared.models.User');
goog.provide('upvote.shared.models.Vote');


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   idType: string,
 *   blockableHash: string,
 *   fileName: string,
 *   publisher: string,
 *   productName: string,
 *   version: string,
 *   occurredDt: string,
 *   updatedDt: string,
 *   recordedDt: string,
 *   score: number,
 *   flagged: boolean,
 *   state: string,
 *   stateChangeDt: string,
 *   notes: !Array<string>,
 *   isVotingAllowed: boolean,
 *   votingProhibitedReason: string,
 *
 *   description: string,
 *   fileType: string,
 *   firstSeenComputer: string,
 *   firstSeenPath: string,
 *   isInstaller: boolean,
 *   md5: string,
 *   productVersion: string,
 *   sha1: string
 * }}
 */
upvote.shared.models.Bit9Binary;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   idType: string,
 *   blockableHash: string,
 *   fileName: string,
 *   publisher: string,
 *   productName: string,
 *   version: string,
 *   occurredDt: string,
 *   updatedDt: string,
 *   recordedDt: string,
 *   score: number,
 *   flagged: boolean,
 *   state: string,
 *   stateChangeDt: string,
 *   notes: !Array<string>,
 *   isVotingAllowed: boolean,
 *   votingProhibitedReason: string,
 *
 *   bundleId: string,
 * }}
 */
upvote.shared.models.SantaBlockable;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   idType: string,
 *   blockableHash: string,
 *   fileName: string,
 *   publisher: string,
 *   productName: string,
 *   version: string,
 *   occurredDt: string,
 *   updatedDt: string,
 *   recordedDt: string,
 *   score: number,
 *   flagged: boolean,
 *   state: string,
 *   stateChangeDt: string,
 *   notes: !Array<string>,
 *   isVotingAllowed: boolean,
 *   votingProhibitedReason: string,
 *
 *   commonName: string,
 *   organization: string,
 *   organizationUnit: string,
 *   validFromDt: string,
 *   validUntilDt: string
 * }}
 */
upvote.shared.models.SantaCertificate;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   idType: string,
 *   blockableHash: string,
 *   fileName: string,
 *   publisher: string,
 *   productName: string,
 *   version: string,
 *   occurredDt: string,
 *   updatedDt: string,
 *   recordedDt: string,
 *   score: number,
 *   flagged: boolean,
 *   state: string,
 *   stateChangeDt: string,
 *   notes: !Array<string>,
 *   isVotingAllowed: boolean,
 *   votingProhibitedReason: string,
 *
 *   name: string,
 *   shortVersion: string,
 *   bundleId: string,
 *   uploadedDt: string,
 *   hasBeenUploaded: boolean
 * }}
 */
upvote.shared.models.SantaBundle;


/**
 * @typedef {(
 *   upvote.shared.models.Bit9Binary|
 *   upvote.shared.models.SantaBlockable|
 *   upvote.shared.models.SantaCertificate|
 *   upvote.shared.models.SantaBundle
 * )}
 */
upvote.shared.models.AnyBlockable;


/**
 * @typedef {{
 *   id: string,
 *   blockableKey: string,
 *   certId: string,
 *   certKey: string,
 *   fileName: string,
 *   relPath: string,
 *   fullPath: string
 * }}
 */
upvote.shared.models.SantaBundleBinary;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   blockableId: string,
 *   eventType: string,
 *   recordedDt: string,
 *   hostId: string,
 *   fileName: string,
 *   filePath: string,
 *   publisher: string,
 *   version: string,
 *   executingUser: string,
 *
 *   hostname: string
 * }}
 */
upvote.shared.models.Bit9Event;


/**
 * @typedef {{
 *   agentBundleId: string,
 *   dataUrl: string,
 *   downloadedDt: string,
 *   refererUrl: string,
 * }}
 */
upvote.shared.models.QuarantineMetadata;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   blockableId: string,
 *   eventType: string,
 *   recordedDt: string,
 *   hostId: string,
 *   fileName: string,
 *   filePath: string,
 *   publisher: string,
 *   version: string,
 *   executingUser: string,
 *
 *   quarantine: ?upvote.shared.models.QuarantineMetadata,
 * }}
 */
upvote.shared.models.SantaEvent;


/**
 * @typedef {(
 *   upvote.shared.models.Bit9Event|
 *   upvote.shared.models.SantaEvent
 * )}
 */
upvote.shared.models.AnyEvent;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *
 *   recorded_dt: string,
 *   state: string,
 *   details: !Array<string>
 * }}
 */
upvote.shared.models.Record;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *
 *   id: string,
 *   creationDt: string,
 *   deactivationDt: string,
 *   state: string,
 *   history: !Array<!upvote.shared.models.Record>
 * }}
 */
upvote.shared.models.Exemption;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   hostname: string,
 *   recordedDt: string,
 *
 *   serialNum: string,
 *   primaryUser: string,
 *   santaVersion: string,
 *   osVersion: string,
 *   osBuild: string,
 *   lastPreflightDt: string,
 *   lastPreflightIp: string,
 *   lastPostflightDt: string,
 *   clientMode: string,
 *   shouldUploadLogs: boolean,
 *   directoryWhitelistRegex: string,
 *   directoryBlacklistRegex: string,
 *   ruleSyncDt: string,
 *   hidden: boolean
 * }}
 */
upvote.shared.models.SantaHost;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   hostname: string,
 *   recordedDt: string,
 *   hidden: boolean,
 *   exemption: ?upvote.shared.models.Exemption
 * }}
 */
upvote.shared.models.Host;


/**
 * @typedef {(
 *   upvote.shared.models.SantaHost|
 *   upvote.shared.models.Host
 * )}
 */
upvote.shared.models.AnyHost;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   recordedDt: string,
 *   voteWeight: number,
 *   roles: !Array<string>,
 *   lastVoteDt: string,
 *   name: string,
 *   permissions: !Array<string>,
 *   isAdmin: boolean
 * }}
 */
upvote.shared.models.User;


/**
 * @typedef {{
 *   class_: !Array<string>,
 *   operatingSystemFamily: string,
 *
 *   id: string,
 *   recordedDt: string,
 *   candidateType: string,
 *   weight: number,
 *   userEmail: string,
 *   wasYesVote: boolean,
 *   key: string,
 * }}
 */
upvote.shared.models.Vote;
