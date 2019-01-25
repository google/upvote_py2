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

goog.require('upvote.exemptions.ExemptionService');

goog.scope(() => {
const ExemptionService = upvote.exemptions.ExemptionService;


describe('Exemption Service', () => {
  let http, httpBackend;
  let exmService;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.exemptions.module.name);

    angular.mock.inject(($http, $httpBackend) => {
      // Store injected components.
      http = $http;
      httpBackend = $httpBackend;
    });
  });

  beforeEach(() => {
    exmService = new ExemptionService(http);
  });

  afterEach(function() {
    httpBackend.flush();
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('should request the proper URL', () => {

    it('when retrieving an existing exemption', () => {
      httpBackend.expectGET('/api/web/exemptions/abc').respond(200);
      exmService.getExemption('abc');
    });

    describe('when requesting an exemption', () => {
      it('', () => {
        httpBackend.expectPOST('/api/web/exemptions/abc/request')
            .respond((method, url, data, headers, params) => {
              expect(data.search(/reason=DEVELOPER_MACOS/)).not.toBe(-1);
              expect(data.search(/otherText/)).toBe(-1);
              return [200, {}];
            });
        exmService.requestExemption(
            'abc', {'reason': 'DEVELOPER_MACOS', 'otherText': null});
      });

      it('of type OTHER', () => {
        httpBackend.expectPOST('/api/web/exemptions/abc/request')
            .respond((method, url, data, headers, params) => {
              expect(data.search(/reason=OTHER/)).not.toBe(-1);
              expect(data.search(/otherText=FOO/)).not.toBe(-1);
              return [200, {}];
            });
        exmService.requestExemption(
            'abc', {'reason': 'OTHER', 'otherText': 'FOO'});
      });
    });

    it('when cancelling an exemption', () => {
      httpBackend.expectPOST('/api/web/exemptions/abc/cancel')
          .respond((method, url, data, headers, params) => {
            expect(data).toBeFalsy();
            return [200, {}];
          });
      exmService.cancelExemption('abc');
    });

  });
});
});  // goog.scope
