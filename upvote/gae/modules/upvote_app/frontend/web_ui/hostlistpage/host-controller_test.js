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

goog.require('upvote.errornotifier.module');
goog.require('upvote.exemptions.module');
goog.require('upvote.hostlistpage.HostListController');
goog.require('upvote.hosts.ProtectionLevel');
goog.require('upvote.hosts.module');
goog.require('upvote.shared.Page');

goog.scope(() => {
const HostListController = upvote.hostlistpage.HostListController;
const ProtectionLevel = upvote.hosts.ProtectionLevel;


describe('Host List Controller', () => {
  let hostService, errorService, location, q, rootScope, page;
  let filter, ctrl;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.errornotifier.module.name);
    angular.mock.module(upvote.exemptions.module.name);
    angular.mock.module(upvote.hosts.module.name);

    angular.mock.inject(
        (_hostService_, _errorService_, $location, $q, $rootScope, $filter) => {
          // Store injected components.
          hostService = _hostService_;
          errorService = _errorService_;
          location = $location;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();
          filter = $filter;

          // Create spies.
          hostService.getAssociatedHosts =
              jasmine.createSpy('getAssociatedHosts');
          hostService.getProtectionLevel =
              jasmine.createSpy('getProtectionLevel');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          errorService.createToastFromError =
              jasmine.createSpy('createToastFromError');
        });
  });

  let setHosts = (hosts) => {
    if (hosts != null) {
      hostService.getAssociatedHosts['and']['returnValue'](
          q.resolve({'data': hosts}));
    } else {
      hostService.getAssociatedHosts['and']['returnValue'](q.reject());
    }
  };

  // Set the default initialization to be one without results
  beforeEach(() => {
    setHosts([]);
  });

  let buildController = () =>
      new HostListController(hostService, errorService, location, page, filter);

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
  let getSantaHost = (opt_properties) =>
      Object.assign(getHost({'class_': ['Host', 'SantaHost']}), opt_properties);

  describe('should display an error notifiction', () => {
    it('when host initialization fails', () => {
      setHosts(null);

      ctrl = buildController();
      rootScope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });
  });

  describe('should initialize the host list', () => {
    it('when there are no results', () => {
      ctrl = buildController();
      rootScope.$apply();
      rootScope.$apply();

      expect(hostService.getAssociatedHosts['calls'].count()).toEqual(1);
      expect(ctrl.hosts).toEqual([]);
    });

    it('when there are results', () => {
      let hosts = [getSantaHost({'id': 'foo'}), getSantaHost({'id': 'bar'})];
      setHosts(hosts);
      ctrl = buildController();
      rootScope.$apply();
      rootScope.$apply();

      expect(hostService.getAssociatedHosts['calls'].count()).toEqual(1);
      expect(ctrl.hosts).toEqual(hosts);
    });
  });

  describe('should display the correct protection text', () => {
    it('when on full protection', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.FULL);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionText(fakeHost)).toEqual('Full Protection');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when on developer mode', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.DEVMODE);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionText(fakeHost)).toEqual('Developer Mode');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when on minimal protection', () => {
      const fakeHost = {
        'exemption': {
          'deactivationDt': '2020-01-02T12:00Z',
        },
      };
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.MINIMAL);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionText(fakeHost))
          .toEqual('Minimal Protection Until Thu, Jan 02, 2020');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when no host is provided', () => {
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.UNKNOWN);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionText(null)).toEqual('Unknown');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });
  });

  describe('should use the correct protection class', () => {
    it('when on full protection', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel['FULL']);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionClass(fakeHost)).toEqual('full-protection');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when on developer mode', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel['DEVMODE']);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionClass(fakeHost)).toEqual('developer-mode');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when on minimal protection', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel['MINIMAL']);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionClass(fakeHost)).toEqual('minimal-protection');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });

    it('when protection level is unknown', () => {
      const fakeHost = {};
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel['UNKNOWN']);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.getProtectionClass(fakeHost)).toEqual('minimal-protection');
      expect(hostService.getProtectionLevel['calls'].count()).toEqual(1);
    });
  });

  describe('should navigate to the modify protection page', () => {
    it('when provided with a valid ', () => {
      ctrl = buildController();
      ctrl.goToModifyProtectionPage('abc');
      rootScope.$apply();

      expect(location.path()).toEqual('/hosts/abc/modify-protection');
    });
  });

  describe('should navigate to the blockable page', () => {
    it('when provided with a valid ', () => {
      ctrl = buildController();
      ctrl.goToBlockablesPage('abc');
      rootScope.$apply();

      expect(location.path()).toEqual('/hosts/abc/blockables');
    });
  });
});
});  // goog.scope
