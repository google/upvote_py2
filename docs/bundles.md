## Bundle Voting

Application bundles (aka `.app`s) are the primary method of application
packaging on macOS. Bundles are essentially directories with a `.app` extension
and a [fixed structure][1] defined by Apple. They can be quite large: A
relatively small application like the built-in Calendar app contains over 2,500
files, with 3 executables while larger bundles like Apple's Xcode or Adobe's
Creative Suite can contain well over 100,000 files and thousands of executables.

This presents an issue for binary whitelisting as each binary would normally
need to be whitelisted individually. One could whitelist the signing
certificate(s) used in the bundle but far too many macOS apps neglect to sign
all their binaries. Any unsigned binary would then cause a Santa block. All
told, these persistent, unnecessary Santa blocks are a hassle for users and a
hinderance to social whitelisting.

The solution was bundle voting, a feature in Santa and Upvote that groups all of
a bundle's binaries into a single Blockable for which policy can be set. Users
who get a bundle execution blocked will be referred to a separate voting page
with bundle-specific displays and be able to whitelist the application as a
whole. One implementation note: While Upvote does create bundle-type Rule
entities to represent this policy, Santa has no mechanism to block executions on
the granularity of bundles. To achieve an equivalent policy effect, Upvote
expands each bundle policy into many binary policies at sync time to send down
to Santa clients.

Due to the implementation and security considerations of the feature, there are
a few restrictions on bundle voting:

-   Downvoting is prohibited
    -   Blacklist policies can be created by downvoting individual binaries or
        the signing certificate
-   Resetting is not supported
-   If any constituent binary of the bundle is flagged or is signed by a flagged
    certificate, voting is prohibited

Bundle support (detection, scanning, and upload) is a configuration option in
the Santa client and is enabled by default by Upvote. To disable bundle voting,
set the `ENABLE_BUNDLES` setting to `False`.

For information on the client-side functionality and implementation, see the
[Santa docs page][2].

[1]: https://developer.apple.com/library/content/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html
[2]: https://santa.readthedocs.io/en/latest/details/santabs/
