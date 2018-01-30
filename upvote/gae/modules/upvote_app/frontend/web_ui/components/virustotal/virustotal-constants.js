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

goog.provide('upvote.virustotal.BundleReport');
goog.provide('upvote.virustotal.CompletedReport');
goog.provide('upvote.virustotal.IncompleteReport');
goog.provide('upvote.virustotal.Report');
goog.provide('upvote.virustotal.ResponseCode');
goog.provide('upvote.virustotal.Scan');


/** @enum {number} */
upvote.virustotal.ResponseCode = {
  'QUEUED': -2,
  'UNKNOWN': 0,
  'KNOWN': 1
};


/**
 * @typedef {{
 *   detected: boolean,
 *   version: string,
 *   result: string,
 *   update: string
 * }}
 */
upvote.virustotal.Scan;


/**
 * @typedef {{
 *   responseCode: upvote.virustotal.ResponseCode,
 *   verboseMsg: string,
 *   resource: string,
 *   scan_id: string,
 *   md5: string,
 *   sha1: string,
 *   sha256: string,
 *   scanDate: string,
 *   positives: number,
 *   total: number,
 *   scans: !Object<string, upvote.virustotal.Scan>,
 *   permalink: string
 * }}
 */
upvote.virustotal.CompletedReport;


/**
 * @typedef {{
 *   responseCode: upvote.virustotal.ResponseCode,
 *   verboseMsg: string,
 *   resource: string
 * }}
 */
upvote.virustotal.IncompleteReport;


/**
 * @typedef {(
 *   upvote.virustotal.CompletedReport|
 *   upvote.virustotal.IncompleteReport
 * )}
 */
upvote.virustotal.Report;


/**
 * @typedef {{
 *   responseCode: upvote.virustotal.ResponseCode,
 *   positives: number,
 *   total: number,
 *   reports: !Object<string, !upvote.virustotal.Report>
 * }}
 */
upvote.virustotal.BundleReport;
