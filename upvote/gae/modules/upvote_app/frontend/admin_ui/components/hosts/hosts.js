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

goog.provide('upvote.admin.hosts.module');

goog.require('upvote.admin.hosts.HostQueryResource');
goog.require('upvote.admin.hosts.HostResource');
goog.require('upvote.admin.hosts.prettifyMode');
goog.require('upvote.admin.hosts.prettifyUuid');
goog.require('upvote.admin.hosts.uvHostCard');


/** @type {!angular.Module} */
upvote.admin.hosts.module =
    angular.module('upvote.admin.hosts', ['ngResource'])
        .factory('hostResource', upvote.admin.hosts.HostResource)
        .factory('hostQueryResource', upvote.admin.hosts.HostQueryResource)
        .directive('uvHostCard', upvote.admin.hosts.uvHostCard)
        .filter('prettifyMode', () => upvote.admin.hosts.prettifyMode)
        .filter('prettifyUuid', () => upvote.admin.hosts.prettifyUuid);
