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
goog.provide('upvote.admin.app.module');

goog.require('upvote.admin.app.MainController');
goog.require('upvote.admin.app.routeProvider');
goog.require('upvote.admin.blockablepage.BlockableController');
goog.require('upvote.admin.blockables.module');
goog.require('upvote.admin.common.module');
goog.require('upvote.admin.dashboard.DashboardController');
goog.require('upvote.admin.emergency.module');
goog.require('upvote.admin.emergencypage.EmergencyController');
goog.require('upvote.admin.eventpage.EventController');
goog.require('upvote.admin.events.module');
goog.require('upvote.admin.hostpage.HostController');
goog.require('upvote.admin.hosts.module');
goog.require('upvote.admin.rulepage.RuleController');
goog.require('upvote.admin.rules.module');
goog.require('upvote.admin.settings.module');
goog.require('upvote.admin.settingspage.SettingsController');
goog.require('upvote.admin.templates.module');
goog.require('upvote.admin.users.module');
goog.require('upvote.admin.votepage.VoteController');
goog.require('upvote.admin.votes.module');
goog.require('upvote.app.httpProvider');
goog.require('upvote.errornotifier.module');
goog.require('upvote.hosts.module');
goog.require('upvote.listing.module');
goog.require('upvote.shared.Page');
goog.require('upvote.sidenav.module');
goog.require('upvote.titlebar.module');

goog.scope(() => {


/** The main application module. */
upvote.admin.app.module = angular.module('upvote.admin.app', [
  upvote.admin.blockables.module.name,
  upvote.admin.common.module.name,
  upvote.admin.emergency.module.name,
  upvote.admin.events.module.name,
  upvote.admin.hosts.module.name,
  upvote.admin.rules.module.name,
  upvote.admin.settings.module.name,
  upvote.admin.templates.module.name,
  upvote.admin.users.module.name,
  upvote.admin.votes.module.name,
  upvote.errornotifier.module.name,
  upvote.hosts.module.name,
  upvote.listing.module.name,
  upvote.sidenav.module.name,
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
 * Initializes the application.
 * NOTE: Should be called from the index file.
 * @param {string} username The name of the user sent form the server.
 * @export
 */
upvote.admin.app.start = (username) => {
  const module = upvote.admin.app.module;

  module.constant('username', username);
  module.value('page', new upvote.shared.Page());

  module.config(upvote.admin.app.routeProvider);
  module.config(upvote.app.httpProvider);
  module.config(upvote.app.registerIcons);
  module.config(upvote.app.configureColorTheme);

  // Register all controllers
  module.controller(
      'BlockableController', upvote.admin.blockablepage.BlockableController);
  module.controller(
      'DashboardController', upvote.admin.dashboard.DashboardController);
  module.controller(
      'EmergencyController', upvote.admin.emergencypage.EmergencyController);
  module.controller('EventController', upvote.admin.eventpage.EventController);
  module.controller('HostController', upvote.admin.hostpage.HostController);
  module.controller('MainController', upvote.admin.app.MainController);
  module.controller('RuleController', upvote.admin.rulepage.RuleController);
  module.controller(
      'SettingsController', upvote.admin.settingspage.SettingsController);
  module.controller('VoteController', upvote.admin.votepage.VoteController);
};
});  // goog.scope
