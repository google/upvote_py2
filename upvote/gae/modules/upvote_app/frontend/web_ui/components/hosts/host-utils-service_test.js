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

goog.require('upvote.app.constants');
goog.require('upvote.hosts.HostUtilsService');

goog.scope(() => {
const HostUtilsService = upvote.hosts.HostUtilsService;

describe('Host Utils Service', () => {
  let hostUtilsService;

  beforeEach(() => {
    hostUtilsService = new HostUtilsService();
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

  describe('should supply the correct platform Image URL', () => {
    it('for Santa hosts', () => {
      let fakeHost = getSantaHost();

      expect(hostUtilsService.getPlatformImageUrl(fakeHost))
          .toBe('/static/images/apple_logo.svg');
    });

    it('for Bit9 hosts', () => {
      let fakeHost = getBit9Host();

      expect(hostUtilsService.getPlatformImageUrl(fakeHost))
          .toBe('/static/images/windows_logo.svg');
    });
  });

  describe('should reflect the proper host type', () => {
    it('for Santa hosts', () => {
      let fakeHost = getSantaHost();

      expect(hostUtilsService.isSantaHost(fakeHost)).toBe(true);
      expect(hostUtilsService.isBit9Host(fakeHost)).toBe(false);
    });

    it('for Bit9 hosts', () => {
      let fakeHost = getBit9Host();

      expect(hostUtilsService.isSantaHost(fakeHost)).toBe(false);
      expect(hostUtilsService.isBit9Host(fakeHost)).toBe(true);
    });

    it('for other hosts', () => {
      let fakeHost = getHost();

      expect(hostUtilsService.isSantaHost(fakeHost)).toBe(false);
      expect(hostUtilsService.isBit9Host(fakeHost)).toBe(false);
    });
  });

  describe('should return', () => {
    describe('whether the Host is in lockdown mode', () => {
      describe('for a Santa host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getSantaHost({'clientMode': 'LOCKDOWN'});

          expect(hostUtilsService.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getSantaHost({'clientMode': 'not anything'});

          expect(hostUtilsService.isInLockdown(fakeHost)).toBe(false);
        });
      });

      describe('for a Bit9 host', () => {
        it('when it is in lockdown', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'LOCKDOWN'});

          expect(hostUtilsService.isInLockdown(fakeHost)).toBe(true);
        });

        it('when it is in an unexpected mode', () => {
          let fakeHost = getBit9Host({'policyEnforcementLevel': 'nothing'});

          expect(hostUtilsService.isInLockdown(fakeHost)).toBe(false);
        });
      });
    });

    it('false for unexpected host types', () => {
      let fakeHost = getHost({'clientMode': 'LOCKDOWN'});

      expect(hostUtilsService.isInLockdown(fakeHost)).toBe(false);
    });
  });
});
});  // goog.scope
