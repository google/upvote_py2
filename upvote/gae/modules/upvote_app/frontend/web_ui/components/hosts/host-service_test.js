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
goog.require('upvote.hosts.ProtectionLevel');
goog.require('upvote.hosts.module');

goog.scope(() => {
const HostService = upvote.hosts.HostService;
const ProtectionLevel = upvote.hosts.ProtectionLevel;

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
    httpBackend.verifyNoOutstandingExpectation();
    httpBackend.verifyNoOutstandingRequest();
  });

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getHost = (opt_properties) =>
      Object.assign({'id': 'foo', 'class_': ['Host']}, opt_properties);

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getBit9Host = (opt_properties) => Object.assign(
      getHost({
        'class_': ['Host', 'Bit9Host'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.WINDOWS,
      }),
      opt_properties);

  /**
   * @param {?Object=} opt_properties
   * @return {!Object}
   */
  let getSantaHost = (opt_properties) => Object.assign(
      getHost({
        'class_': ['Host', 'SantaHost'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS,
      }),
      opt_properties);

  describe('should request the proper URL', () => {
    it('when retrieving a host by its ID', () => {
      httpBackend.expectGET('/api/web/hosts/abc').respond(200);
      hostService.get('abc');
      httpBackend.flush();
    });

    describe('when getting associated hosts', () => {
      it('for a given user', () => {
        httpBackend.expectGET('/api/web/hosts/associated/user@foo.com')
            .respond(200);
        hostService.getAssociatedHosts('user@foo.com');
        httpBackend.flush();
      });

      it('for the current user', () => {
        httpBackend.expectGET('/api/web/hosts/associated').respond(200);
        hostService.getAssociatedHosts();
        httpBackend.flush();
      });
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
        httpBackend.flush();
      });
    });

    describe('when changing hidden to', () => {
      it('true', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/hidden/true').respond(200);
        hostService.setHidden('12345', true);
        httpBackend.flush();
      });

      it('false', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/hidden/false').respond(200);
        hostService.setHidden('12345', false);
        httpBackend.flush();
      });
    });

    describe('when changing transitive to', () => {
      it('true', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/transitive/true')
            .respond(200);
        hostService.setTransitive('12345', true);
        httpBackend.flush();
      });

      it('false', () => {
        httpBackend.expectPUT('/api/web/hosts/12345/transitive/false')
            .respond(200);
        hostService.setTransitive('12345', false);
        httpBackend.flush();
      });
    });
  });

  describe('should supply the correct platform Image URL', () => {
    it('for Santa hosts', () => {
      let fakeHost = getSantaHost();

      expect(hostService.getPlatformImageURL(fakeHost))
          .toBe('/static/images/apple_logo.svg');
    });

    it('for Bit9 hosts', () => {
      let fakeHost = getBit9Host();

      expect(hostService.getPlatformImageURL(fakeHost))
          .toBe('/static/images/windows_logo.svg');
    });
  });

  describe('should reflect the proper host type', () => {
    it('for Santa hosts', () => {
      let fakeHost = getSantaHost();

      expect(hostService.isSantaHost(fakeHost)).toBe(true);
      expect(hostService.isBit9Host(fakeHost)).toBe(false);
    });

    it('for Bit9 hosts', () => {
      let fakeHost = getBit9Host();

      expect(hostService.isSantaHost(fakeHost)).toBe(false);
      expect(hostService.isBit9Host(fakeHost)).toBe(true);
    });

    it('for other hosts', () => {
      let fakeHost = getHost();

      expect(hostService.isSantaHost(fakeHost)).toBe(false);
      expect(hostService.isBit9Host(fakeHost)).toBe(false);
    });
  });

  describe('should return', () => {
    describe('whether the Host is in lockdown mode', () => {
      describe('for a Santa host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getSantaHost({'clientMode': 'LOCKDOWN'});

          expect(hostService.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getSantaHost({'clientMode': 'not anything'});

          expect(hostService.isInLockdown(fakeHost)).toBe(false);
        });
      });

      describe('for a Bit9 host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'LOCKDOWN'});

          expect(hostService.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'nothing'});

          expect(hostService.isInLockdown(fakeHost)).toBe(false);
        });
      });
    });

    it('false for unexpected host types', () => {
      let fakeHost = getHost({'clientMode': 'LOCKDOWN'});

      expect(hostService.isInLockdown(fakeHost)).toBe(false);
    });
  });

  describe('should indicate if host has an approved exemption', () => {
    it('when no exemption exists', () => {
      let fakeHost = {};
      expect(hostService.hasApprovedExemption(fakeHost)).toBe(false);
    });

    it('when the exemption is not approved', () => {
      let fakeHost = {
        'exemption': {
          'state': 'CANCELLED',
        },
      };
      expect(hostService.hasApprovedExemption(fakeHost)).toBe(false);
    });

    it('when the exemption is approved', () => {
      let fakeHost = {
        'exemption': {
          'state': 'APPROVED',
        },
      };
      expect(hostService.hasApprovedExemption(fakeHost)).toBe(true);
    });
  });

  describe('should indicate if transitive whitelisting enabled', () => {
    it('for Bit9 hosts', () => {
      let fakeHost = {
        'class_': ['Host', 'Bit9Host'],
      };
      expect(hostService.isTransitiveWhitelistingEnabled(fakeHost)).toBe(false);
    });

    it('when it is enabled', () => {
      let fakeHost = {
        'class_': ['Host', 'SantaHost'],
        'transitiveWhitelistingEnabled': true,
      };
      expect(hostService.isTransitiveWhitelistingEnabled(fakeHost)).toBe(true);
    });

    it('when it is disabled', () => {
      let fakeHost = {
        'class_': ['Host', 'SantaHost'],
        'transitiveWhitelistingEnabled': false,
      };
      expect(hostService.isTransitiveWhitelistingEnabled(fakeHost)).toBe(false);
    });
  });

  describe('should indicate the correct protection level', () => {
    it('when a host has an approved exemption', () => {
      let fakeHost = {
        'class_': ['Host', 'SantaHost'],
        'exemption': {
          'state': 'APPROVED',
        },
        'transitiveWhitelistingEnabled': false,
      };
      expect(hostService.getProtectionLevel(fakeHost))
          .toBe(ProtectionLevel['MINIMAL']);
    });

    it('when a host has transitive whitelisting enabled', () => {
      let fakeHost = {
        'class_': ['Host', 'SantaHost'],
        'exemption': {
          'state': 'CANCELLED',
        },
        'transitiveWhitelistingEnabled': true,
      };
      expect(hostService.getProtectionLevel(fakeHost))
          .toBe(ProtectionLevel['DEVMODE']);
    });

    it('when a host is fully protected', () => {
      let fakeHost = {
        'class_': ['Host', 'SantaHost'],
        'exemption': {
          'state': 'CANCELLED',
        },
        'transitiveWhitelistingEnabled': false,
      };
      expect(hostService.getProtectionLevel(fakeHost))
          .toBe(ProtectionLevel['FULL']);
    });

    it('when a host is not provided', () => {
      expect(hostService.getProtectionLevel(null))
          .toBe(ProtectionLevel['UNKNOWN']);
    });
  });

});
});  // goog.scope
