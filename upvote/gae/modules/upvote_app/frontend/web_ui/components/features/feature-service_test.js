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

goog.setTestOnly();

goog.require('upvote.features.FeatureService');

goog.scope(() => {
const FeatureService = upvote.features.FeatureService;


describe('Feature Service', () => {
  let http, httpBackend;
  let featureService;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.features.module.name);

    angular.mock.inject(($http, $httpBackend) => {
      // Store injected components.
      http = $http;
      httpBackend = $httpBackend;
    });
  });

  beforeEach(() => {
    featureService = new FeatureService(http);
  });

  afterEach(function() {
    httpBackend.flush();
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('should request the proper URL', () => {
    it('when checking availability', () => {
      httpBackend.expectGET('/api/web/features/valid').respond(200);
      featureService.available('valid');
    });
  });
});
});  // goog.scope
