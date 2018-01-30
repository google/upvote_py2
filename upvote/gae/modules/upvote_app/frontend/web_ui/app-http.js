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

goog.provide('upvote.app.httpProvider');

goog.scope(() => {

/**
 * Converts POST data to a x-www-form-urlencoded serialized Object if provided.
 * @param {?Object} data Data object to be form encoded.
 * @return {string|Object} Data as an x-www-form-urlencoded string.
 */
let transformToFormEncoded = (data) => {
  /**
   * Converts a single object to x-www-form-urlencoded serialization.
   * @param {Object} obj Data object to be form encoded.
   * @return {string} data Data as an x-www-form-urlencoded string.
   */
  let serialize = (obj) => {
    let entries = [];

    for (let name in obj) {
      let value = obj[name];

      if (value instanceof Array || value instanceof Object) {
        for (let subName in value) {
          let subValue = value[subName];
          let fullSubName = name + `[${subName}]`;
          let innerObj = {};
          innerObj[fullSubName] = subValue;
          entries.push(serialize(innerObj));
        }
      } else if (value !== undefined && value !== null) {
        let entry = encodeURIComponent(name) + '=' + encodeURIComponent(value);
        entries.push(entry);
      }
    }

    return entries.join('&');
  };

  if (goog.isObject(data) && String(data) !== '[object File]') {
    return serialize(data);
  } else {
    return data;
  }
};


/**
 * Configure request headers and encodes AJAX requests.
 * @param {angular.$HttpProvider} $httpProvider Angular provider.
 * @export
 * @ngInject
 */
upvote.app.httpProvider = ($httpProvider) => {
  // Use x-www-form-urlencoded Content-Type
  $httpProvider['defaults']['headers']['post']['Content-Type'] =
      'application/x-www-form-urlencoded;charset=utf-8';

  // Override $http service's default transformRequest
  $httpProvider['defaults']['transformRequest'] = [transformToFormEncoded];
};
});  // goog.scope
