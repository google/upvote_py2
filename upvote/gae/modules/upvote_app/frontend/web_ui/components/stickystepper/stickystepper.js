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

goog.module('upvote.stickystepper.module');
goog.module.declareLegacyNamespace();

const StickyStepperController = goog.require('upvote.stickystepper.StickyStepperController');
const steppers = goog.require('StepperCtrl');


// Patch mdStepper to use the StickyStepperController instead.
angular.module('mdSteppers').decorator('mdStepperDirective', [
  '$delegate',
  ($delegate) => {
    let baseDirective = $delegate[0];
    // Overwrite the controller to use our custom one.
    baseDirective.controller = StickyStepperController;

    // Extend the link method to add an extra class.
    let origLink = baseDirective.link;
    baseDirective.compile = (cElem, cAttr) => {
      return (scope, elem, attrs) => {
        elem.addClass('uv-sticky-stepper');
        origLink && origLink.apply(baseDirective, [scope, elem, attrs]);
      };
    };
    return [baseDirective];
  }
]);


/**
 * Declare a dummy module that bundles all mdStepper dependencies into a single,
 * non-typescript source.
 * @type {!angular.Module}
 */
const module = angular.module('upvote.stickystepper', [
  'mdSteppers',
]);

/** @const */
exports = module;
