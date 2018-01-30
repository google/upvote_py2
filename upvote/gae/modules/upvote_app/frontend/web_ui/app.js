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
 * @fileoverview App setup code.
 */
goog.provide('upvote.app.module');

goog.require('upvote.app.MainController');
goog.require('upvote.app.httpProvider');
goog.require('upvote.app.routeProvider');
goog.require('upvote.blockables.module');
goog.require('upvote.common.module');
goog.require('upvote.detailpage.BlockableDetailsController');
goog.require('upvote.errornotifier.module');
goog.require('upvote.events.module');
goog.require('upvote.hostblockablespage.HostBlockableListController');
goog.require('upvote.hostlistpage.HostListController');
goog.require('upvote.hostrequestpage.HostRequestController');
goog.require('upvote.hosts.module');
goog.require('upvote.listing.module');
goog.require('upvote.listpage.BlockableListController');
goog.require('upvote.morefooter.module');
goog.require('upvote.packagecontents.module');
goog.require('upvote.packageresults.module');
goog.require('upvote.settings.module');
goog.require('upvote.shared.Page');
goog.require('upvote.sidenav.module');
goog.require('upvote.signalindicator.module');
goog.require('upvote.statechip.module');
goog.require('upvote.stickystepper.module');
goog.require('upvote.templates.module');
goog.require('upvote.titlebar.module');
goog.require('upvote.users.module');
goog.require('upvote.virustotal.module');
goog.require('upvote.votes.module');


/** The main application module. */
upvote.app.module = angular.module('upvote.app', [
  upvote.blockables.module.name,
  upvote.common.module.name,
  upvote.errornotifier.module.name,
  upvote.events.module.name,
  upvote.hosts.module.name,
  upvote.listing.module.name,
  upvote.morefooter.module.name,
  upvote.packagecontents.module.name,
  upvote.packageresults.module.name,
  upvote.settings.module.name,
  upvote.sidenav.module.name,
  upvote.signalindicator.module.name,
  upvote.statechip.module.name,

  upvote.stickystepper.module.name,
  upvote.users.module.name,
  upvote.virustotal.module.name,
  upvote.votes.module.name,
  upvote.templates.module.name,
  upvote.titlebar.module.name,
  'ngAnimate',
  'ngRoute',
  'ngResource',
  'ngMaterial',
  'ngSanitize',
]);


/**
 * Registers icons.
 * @param {!md.$mdIconProvider} $mdIconProvider
 * @export
 * @ngInject
 */
upvote.app.registerIcons = function($mdIconProvider) {
  $mdIconProvider.defaultFontSet('material-icons-extended');
  $mdIconProvider.icon('upvote-logo', '/static/images/upvote_logo.svg');
};


/**
 * Registers color theme.
 * @param {!md.$mdThemingProvider} $mdThemingProvider
 * @export
 * @ngInject
 */
upvote.app.configureColorTheme = function($mdThemingProvider) {
  // Set Color theme (Google Blue)
  $mdThemingProvider.definePalette('g-blue', {
    '50': 'e8f0fe',
    '100': 'c6dafc',
    '200': 'a1c2fa',
    '300': '7baaf7',
    '400': '5e97f6',
    '500': '4285f4',
    '600': '3b78e7',
    '700': '3367d6',
    '800': '2a56c6',
    '900': '1c3aa9',
    'A100': '82b1ff',
    'A200': '448aff',
    'A400': '2979ff',
    'A700': '2962ff',
    'contrastDefaultColor': 'light',
    'contrastDarkColors': ['50', '100', '200', '300', '400', 'A100'],
    'contrastLightColors': undefined
  });
  $mdThemingProvider.theme('default').primaryPalette('g-blue');
};


/**
 * The start point of the application.
 * Performs whole initialization of the app.
 * Should be called from the index file.
 * @param {string} username The name of the user sent form the server.
 * @export
 */
upvote.app.start = function(username) {
  let module = upvote.app.module;

  module.constant('username', username);
  module.value('page', new upvote.shared.Page());

  module.config(upvote.app.httpProvider);
  module.config(upvote.app.routeProvider);
  module.config(upvote.app.registerIcons);
  module.config(upvote.app.configureColorTheme);

  // Register all controllers
  module.controller(
      'BlockableDetailsController',
      upvote.detailpage.BlockableDetailsController);
  module.controller(
      'BlockableListController', upvote.listpage.BlockableListController);
  module.controller('MainController', upvote.app.MainController);
  module.controller(
      'HostListController', upvote.hostlistpage.HostListController);
  module.controller(
      'HostRequestController', upvote.hostrequestpage.HostRequestController);
  module.controller(
      'HostBlockableListController',
      upvote.hostblockablespage.HostBlockableListController);
};
