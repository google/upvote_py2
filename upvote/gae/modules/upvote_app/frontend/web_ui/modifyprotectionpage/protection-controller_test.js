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
goog.require('upvote.features.module');
goog.require('upvote.hosts.ProtectionLevel');
goog.require('upvote.hosts.module');
goog.require('upvote.modifyprotectionpage.ModifyProtectionController');
goog.require('upvote.shared.Page');

goog.scope(() => {
const ModProCtrl = upvote.modifyprotectionpage.ModifyProtectionController;
const ProtectionLevel = upvote.hosts.ProtectionLevel;


describe('Modify Protection Controller', () => {
  let exemptionService, hostService, errorService, featureService, location, q;
  let rootScope, page, ctrl;

  beforeEach(/** @suppress {missingProperties} */ () => {
    angular.mock.module(upvote.errornotifier.module.name);
    angular.mock.module(upvote.exemptions.module.name);
    angular.mock.module(upvote.features.module.name);
    angular.mock.module(upvote.hosts.module.name);

    angular.mock.inject(
        (_exemptionService_, _hostService_, _errorService_, _featureService_,
         $location, $q, $rootScope) => {
          // Store injected components.
          exemptionService = _exemptionService_;
          hostService = _hostService_;
          errorService = _errorService_;
          featureService = _featureService_;
          location = $location;
          q = $q;
          rootScope = $rootScope;
          page = new upvote.shared.Page();

          // Create spies.
          hostService.get = jasmine.createSpy('get');
          hostService.setTransitive = jasmine.createSpy('setTransitive');
          hostService.getProtectionLevel =
              jasmine.createSpy('getProtectionLevel');
          exemptionService.requestExemption =
              jasmine.createSpy('requestExemption');
          exemptionService.cancelExemption =
              jasmine.createSpy('cancelExemption');
          errorService.createDialogFromError =
              jasmine.createSpy('createDialogFromError');
          featureService.available = jasmine.createSpy('available');
        });
  });

  let buildController = () => new ModProCtrl(
      exemptionService, hostService, errorService, featureService, location,
      page, rootScope.$new());

  describe('should indicate if Developer Mode is available', () => {
    it('for Santa clients', () => {
      const hostData = {
        'id': 'fakeId',
        'class_': ['Host', 'SantaHost'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isDeveloperModeAvailable()).toBe(true);
    });

    it('for Bit9 clients', () => {
      const hostData = {
        'id': 'fakeId',
        'class_': ['Host', 'Bit9Host'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.WINDOWS,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isDeveloperModeAvailable()).toBe(false);
    });

    it('when the feature is available', () => {
      const hostData = {
        'id': 'fakeId',
        'class_': ['Host', 'SantaHost'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isDeveloperModeAvailable()).toBe(true);
    });

    it('when the feature is not available', () => {
      const hostData = {
        'id': 'fakeId',
        'class_': ['Host', 'SantaHost'],
        'operatingSystemFamily': upvote.app.constants.PLATFORMS.MACOS,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 403}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isDeveloperModeAvailable()).toBe(false);
    });
  });

  describe('should indicate if a given protection level is', () => {
    it('enabled when no host is present', () => {
      hostService.get['and']['returnValue'](q.reject());
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isProtectionLevelEnabled_(ProtectionLevel.FULL)).toBe(true);
    });

    it('enabled when the levels match', () => {
      const hostData = {};
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.FULL);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isProtectionLevelEnabled_(ProtectionLevel.FULL)).toBe(true);
    });

    it('disabled when the levels do not match', () => {
      const hostData = {};
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.DEVMODE);

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.isProtectionLevelEnabled_(ProtectionLevel.FULL)).toBe(false);
    });
  });

  describe('should properly indicate a pending exemption', () => {
    it('if no host is present', () => {
      hostService.get['and']['callFake'](() => q.when({'data': null}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.hasPendingExemption_()).toBe(false);
    });

    it('if the host has no exemption', () => {
      const hostData = {};
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.hasPendingExemption_()).toBe(false);
    });

    it('if the exemption is not pending', () => {
      const hostData = {'exemption': {'state': 'APPROVED'}};
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.hasPendingExemption_()).toBe(false);
    });

    it('if the exemption is pending', () => {
      const hostData = {'exemption': {'state': 'PENDING'}};
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.hasPendingExemption_()).toBe(true);
    });
  });

  it('should set Developer Mode as expected', () => {
    const hostData1 = {
      'id': '12345',
      'transitiveWhitelistingEnabled': false,
    };
    const hostData2 = {
      'id': '12345',
      'transitiveWhitelistingEnabled': true,
    };
    hostService.get['and']['callFake'](() => q.when({'data': hostData1}));
    featureService.available['and']['callFake'](() => q.when({'status': 200}));
    hostService.setTransitive['and']['callFake'](
        () => q.when({'data': hostData2}));

    ctrl = buildController();
    rootScope.$apply();

    expect(ctrl.host.transitiveWhitelistingEnabled).toBe(false);

    ctrl.setDeveloperMode_(true);
    rootScope.$apply();

    expect(hostService.setTransitive['calls'].count()).toEqual(1);
    expect(ctrl.host.transitiveWhitelistingEnabled).toBe(true);
    expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
  });

  describe('should enable Minimal Protection as expected', () => {
    it('when no prior exemption exists', () => {
      const hostData = {
        'id': '12345',
        'transitiveWhitelistingEnabled': false,
      };
      const exmData = {
        'exemption': {'state': 'APPROVED'},
        'transitiveWhitelistingEnabled': false,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      exemptionService.requestExemption['and']['callFake'](
          () => q.when({'data': exmData}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.host.exemption).toBeUndefined();

      ctrl.enableMinimalProtection();
      rootScope.$apply();

      expect(exemptionService.requestExemption['calls'].count()).toEqual(1);
      expect(ctrl.host.exemption.state).toEqual('APPROVED');
      expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
    });

    it('when an inactive prior exemption exists', () => {
      const hostData = {
        'id': '12345',
        'transitiveWhitelistingEnabled': false,
        'exemption': {
          'state': 'CANCELLED',
        },
      };
      const exmData = {
        'exemption': {'state': 'APPROVED'},
        'transitiveWhitelistingEnabled': false,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      exemptionService.requestExemption['and']['callFake'](
          () => q.when({'data': exmData}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.host.exemption.state).toEqual('CANCELLED');

      ctrl.enableMinimalProtection();
      rootScope.$apply();

      expect(exemptionService.requestExemption['calls'].count()).toEqual(1);
      expect(ctrl.host.exemption.state).toEqual('APPROVED');
      expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
    });
  });

  it('should disable Minimal Protection as expected', () => {
    const hostData = {
      'id': '12345',
      'transitiveWhitelistingEnabled': false,
      'exemption': {
        'state': 'APPROVED',
      },
    };
    const exmData = {
      'exemption': {'state': 'CANCELLED'},
      'transitiveWhitelistingEnabled': false,
    };
    hostService.get['and']['callFake'](() => q.when({'data': hostData}));
    featureService.available['and']['callFake'](() => q.when({'status': 200}));
    exemptionService.cancelExemption['and']['callFake'](
        () => q.when({'data': exmData}));

    ctrl = buildController();
    rootScope.$apply();

    expect(ctrl.host.exemption.state).toEqual('APPROVED');

    ctrl.disableMinimalProtection_();
    rootScope.$apply();

    expect(exemptionService.cancelExemption['calls'].count()).toEqual(1);
    expect(ctrl.host.exemption.state).toEqual('CANCELLED');
    expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
  });

  describe('should enable Full Protection when', () => {
    it('Developer Mode is enabled', () => {
      const hostData1 = {
        'id': '12345',
        'transitiveWhitelistingEnabled': true,
      };
      const hostData2 = {
        'id': '12345',
        'transitiveWhitelistingEnabled': false,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData1}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.DEVMODE);
      hostService.setTransitive['and']['callFake'](
          () => q.when({'data': hostData2}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.host.transitiveWhitelistingEnabled).toEqual(true);

      ctrl.enableFullProtection();
      rootScope.$apply();

      expect(hostService.setTransitive['calls'].count()).toEqual(1);
      expect(ctrl.host.transitiveWhitelistingEnabled).toEqual(false);
      expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
    });

    it('Minimal Protection is enabled', () => {
      const hostData = {
        'id': '12345',
        'transitiveWhitelistingEnabled': false,
        'exemption': {
          'state': 'APPROVED',
        },
      };
      const exmData = {
        'exemption': {'state': 'CANCELLED'},
        'transitiveWhitelistingEnabled': false,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      hostService.getProtectionLevel['and']['returnValue'](
          ProtectionLevel.MINIMAL);
      exemptionService.cancelExemption['and']['callFake'](
          () => q.when({'data': exmData}));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.host.exemption.state).toEqual('APPROVED');

      ctrl.enableFullProtection();
      rootScope.$apply();

      expect(exemptionService.cancelExemption['calls'].count()).toEqual(1);
      expect(ctrl.host.exemption.state).toEqual('CANCELLED');
      expect(errorService.createDialogFromError['calls'].count()).toEqual(0);
    });
  });

  describe('should display an error notification', () => {
    it('when host initialization fails', () => {
      hostService.get['and']['returnValue'](q.reject('fail'));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));

      ctrl = buildController();
      rootScope.$apply();

      expect(errorService.createDialogFromError).toHaveBeenCalled();
    });

    it('when setting Developer Mode fails', () => {
      const hostData = {
        'id': '12345',
        'transitiveWhitelistingEnabled': false,
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      hostService.setTransitive['and']['callFake'](() => q.reject('fail'));

      ctrl = buildController();
      rootScope.$apply();

      expect(ctrl.host.transitiveWhitelistingEnabled).toBe(false);

      ctrl.setDeveloperMode_(true);
      rootScope.$apply();

      expect(hostService.setTransitive['calls'].count()).toEqual(1);
      expect(ctrl.host.transitiveWhitelistingEnabled).toBe(false);
      expect(errorService.createDialogFromError['calls'].count()).toEqual(1);
    });

    it('when enabling Minimal Protection fails', () => {
      const hostData = {
        'id': '12345',
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      exemptionService.requestExemption['and']['callFake'](
          () => q.reject('fail'));

      ctrl = buildController();
      rootScope.$apply();

      ctrl.enableMinimalProtection();
      rootScope.$apply();

      expect(errorService.createDialogFromError['calls'].count()).toEqual(1);
    });

    it('when disabling Minimal Protection fails', () => {
      const hostData = {
        'id': '12345',
      };
      hostService.get['and']['callFake'](() => q.when({'data': hostData}));
      featureService.available['and']['callFake'](
          () => q.when({'status': 200}));
      exemptionService.cancelExemption['and']['callFake'](
          () => q.reject('fail'));

      ctrl = buildController();
      rootScope.$apply();

      ctrl.disableMinimalProtection_();
      rootScope.$apply();

      expect(errorService.createDialogFromError['calls'].count()).toEqual(1);
    });
  });
});
});  // goog.scope
