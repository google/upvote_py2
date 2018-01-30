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

goog.require('upvote.hosts.HostService');
goog.require('upvote.hosts.Platform');
goog.require('upvote.hosts.module');

goog.scope(() => {
const HostService = upvote.hosts.HostService;


describe('Host Service', () => {
  let http, httpBackend;
  let hostService;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.hosts.module.name);

    angular.mock.inject(($http, $httpBackend) => {
      // Store injected components.
      http = $http;
      httpBackend = $httpBackend;
    });
  });

  beforeEach(() => {
    hostService = new HostService(http);
  });

  afterEach(function() {
    httpBackend.flush();
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  describe('should request the proper URL', () => {
    it('when retrieving a host by its ID', () => {
      httpBackend.expectGET('/api/web/hosts/abc').respond(200);
      hostService.get('abc');
    });

    it('when retrieving an existing host exception', () => {
      httpBackend.expectGET('/api/web/hosts/abc/request-exception')
          .respond(200);
      hostService.getExistingHostException('abc');
    });

    describe('when requesting a host exception', () => {
      it('', () => {
        httpBackend.expectPOST('/api/web/hosts/abc/request-exception')
            .respond((method, url, data, headers, params) => {
              expect(data.search(/reason=OSX_DEVELOPER/)).not.toBe(-1);
              expect(data.search(/otherText/)).toBe(-1);
              return [200, {}];
            });
        hostService.requestHostException(
            'abc', {'reason': 'OSX_DEVELOPER', 'otherText': null});
      });

      it('of type OTHER', () => {
        httpBackend.expectPOST('/api/web/hosts/abc/request-exception')
            .respond((method, url, data, headers, params) => {
              expect(data.search(/reason=OTHER/)).not.toBe(-1);
              expect(data.search(/otherText=FOO/)).not.toBe(-1);
              return [200, {}];
            });
        hostService.requestHostException(
            'abc', {'reason': 'OTHER', 'otherText': 'FOO'});
      });
    });

    it('when requesting lockdown mode', () => {
      httpBackend.expectPOST('/api/web/hosts/abc/request-lockdown')
          .respond((method, url, data, headers, params) => {
            expect(data).toBeFalsy();
            return [200, {}];
          });
      hostService.requestLockdown('abc');
    });

    describe('when getting associated hosts', () => {
      it('for a given user', () => {
        httpBackend.expectGET('/api/web/hosts/associated/user@foo.com')
            .respond(200);
        hostService.getAssociatedHosts('user@foo.com');
      });

      it('for the current user', () => {
        httpBackend.expectGET('/api/web/hosts/associated').respond(200);
        hostService.getAssociatedHosts();
      });
    });

    it('when requesting event rate', () => {
      httpBackend.expectGET('/api/web/hosts/abc/event-rate').respond(200);
      hostService.getEventRate('abc');
    });

    describe('when querying for hosts', () => {
      it('related to Santa', () => {
        let qParams = {
          'perPage': '10',
          'search': 'abc',
          'searchBase': 'def',
        };
        httpBackend.whenGET(new RegExp('/api/web/hosts/query/santa?.*'))
            .respond((method, url, data, headers, params) => {
              expect(params).toEqual(qParams);
              return [200, {}];
            });

        let params =
            Object.assign({'platform': upvote.hosts.Platform.SANTA}, qParams);
        hostService.search(params);
      });
    });
  });
});
});  // goog.scope
