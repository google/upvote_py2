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

goog.require('upvote.blockables.BlockableService');
goog.require('upvote.blockables.module');

goog.scope(() => {
const BlockableService = upvote.blockables.BlockableService;


describe('Blockable Service', () => {
  let http, httpBackend;
  let blockableService;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.blockables.module.name);

    angular.mock.inject(($http, $httpBackend) => {
      // Store injected components.
      http = $http;
      httpBackend = $httpBackend;
    });
  });

  beforeEach(() => {
    blockableService = new BlockableService(http);
  });

  afterEach(function() {
    httpBackend.flush();
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('should request the proper URL', () => {
    it('when retrieving a blockable by its ID', () => {
      httpBackend.expectGET('/api/web/blockables/abc').respond(200);
      blockableService.get('abc');
    });

    it('when retrieving a package blockable\'s contents', () => {
      httpBackend.expectGET('/api/web/blockables/abc/contents').respond(200);
      blockableService.getPackageContents('abc');
    });

    it('when retrieving a blockable\'s pending status', () => {
      httpBackend.expectGET('/api/web/blockables/abc/pending-state-change')
          .respond(200);
      blockableService.getPending('abc');
    });

    it('when retrieving a blockable\'s pending installer status', () => {
      httpBackend
          .expectGET('/api/web/blockables/abc/pending-installer-state-change')
          .respond(200);
      blockableService.getInstallerPending('abc');
    });

    it('when setting a blockable\'s installer status', () => {
      httpBackend
          .expectPOST(
              '/api/web/blockables/abc/installer-state', {'value': true})
          .respond(200);
      blockableService.setInstallerForce('abc', true);
    });
  });
});
});  // goog.scope
