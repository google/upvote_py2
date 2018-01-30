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

goog.provide('upvote.shared.utils.isCertBlockable');
goog.provide('upvote.shared.utils.isPackageBlockable');

goog.require('upvote.shared.models.AnyBlockable');


/**
 * Return whether a blockable is a cert.
 *
 * @param {?upvote.shared.models.AnyBlockable} blockable
 * @return {boolean}
 */
upvote.shared.utils.isCertBlockable = (blockable) => !!blockable &&
    (blockable['class_'].includes('Certificate') ||
     blockable['class_'].includes('SantaCertificate'));

/**
 * Return whether a blockable is a package.
 *
 * @param {?upvote.shared.models.AnyBlockable} blockable
 * @return {boolean}
 */
upvote.shared.utils.isPackageBlockable = (blockable) =>
    !!blockable && blockable['class_'].includes('Package');
