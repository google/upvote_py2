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

goog.provide('upvote.app.constants');


/**
 * URL prefix for all URLs.
 * @const {string}
 */
upvote.app.constants.URL_PREFIX = '/';


/**
 * URL prefix for all static files.
 * @const {string}
 */
upvote.app.constants.STATIC_URL_PREFIX = '/static/';


/**
 * Prefix for web-facing API URLs.
 * @const {string}
 */
upvote.app.constants.WEB_PREFIX = '/api/web/';


/**
 * The platforms supported.
 * @enum {string}
 */
upvote.app.constants.PLATFORMS = {
  WINDOWS: 'Windows',
  MACOS: 'macOS',
};
