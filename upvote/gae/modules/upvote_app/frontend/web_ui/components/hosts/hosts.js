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

goog.provide('upvote.hosts.module');

goog.require('upvote.app.httpProvider');
goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.HostUtilsService');
goog.require('upvote.hosts.prettifyEnforcementLevel');
goog.require('upvote.hosts.prettifyMode');
goog.require('upvote.hosts.rateToImpactString');


/** @type {!angular.Module} */
upvote.hosts.module =
    angular.module('upvote.hosts', [])
        .service('hostService', upvote.hosts.HostService)
        .service('hostUtilsService', upvote.hosts.HostUtilsService)
        .filter('rateToImpactString', () => upvote.hosts.rateToImpactString)
        .filter('prettifyMode', () => upvote.hosts.prettifyMode)
        .filter(
            'prettifyEnforcementLevel',
            () => upvote.hosts.prettifyEnforcementLevel)
        .config(upvote.app.httpProvider);
