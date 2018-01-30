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

goog.provide('upvote.admin.blockables.module');

goog.require('upvote.admin.blockables.BlockableQueryResource');
goog.require('upvote.admin.blockables.BlockableResource');
goog.require('upvote.admin.blockables.prettifyState');
goog.require('upvote.admin.blockables.prettifyType');
goog.require('upvote.admin.blockables.prettifyVotingProhibitedReason');
goog.require('upvote.admin.blockables.uvBlockableCard');
goog.require('upvote.admin.blockables.uvBlockableListing');
goog.require('upvote.statechip.module');


/** @type {!angular.Module} */
upvote.admin.blockables.module =
    angular
        .module(
            'upvote.admin.blockables',
            [upvote.statechip.module.name, 'ngResource'])
        .factory('blockableResource', upvote.admin.blockables.BlockableResource)
        .factory(
            'blockableQueryResource',
            upvote.admin.blockables.BlockableQueryResource)
        .directive('uvBlockableCard', upvote.admin.blockables.uvBlockableCard)
        .directive(
            'uvBlockableListing', upvote.admin.blockables.uvBlockableListing)
        .directive(
            'uvBlockableHeader', upvote.admin.blockables.uvBlockableHeader)
        .filter('prettifyState', () => upvote.admin.blockables.prettifyState)
        .filter(
            'prettifyVotingProhibitedReason',
            () => upvote.admin.blockables.prettifyVotingProhibitedReason)
        .filter('prettifyType', () => upvote.admin.blockables.prettifyType);
