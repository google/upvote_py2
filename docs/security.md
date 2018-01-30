## Security Discussion

Social whitelisting is, in a lot of ways, contrary to security or IT norms.
Users are given a great deal of authority to make their own security decisions.
Still, users must operate in a secure host environment. Clearly, social
whitelisting offers some tradeoffs between administrative ease and security but
the exact pros and cons bear discussion.

First, there's the big benefit of Lockdown mode which blocks background and/or
unintended executions. Silent exploitation, like drive-by downloads, can be a
significant threat to users regardless of their technical-savvy. For this
reason, Upvote stresses the importance of user intent because even users with
less technical familiarity know when they _didn't_ intend on running any
software.

The next benefit is live comparison against binary analysis services. Without
running any additional antivirus-type solution, Upvote can ensure that all novel
executions get checked against known-malicious sources.

And the last big advantage is that by involving users in the process of
evaluating application safety, they can be educated to become better stewards of
their technology and data.

One risk of this approach is the lessened control over whitelisted applications.
Although this is by-design, Upvote does allow varying degrees of restrictive
policies to be implemented within this social whitelisting system. One can
proactively blacklisting publishers, certs, and binaries of undesirable
applications, raise the whitelisting thresholds, and closely monitor all user
whitelisting actions.

The biggest risk, though, is users whitelisting malware. While this is inherent
in any system where users are given this sort of power, Upvote reduces the
impact of this risk by whitelisting locally by default (exercising the Principle
of Least Privilege). This restricted whitelisting policy will slow an attacker
who manages to get a foothold on a machine in the fleet. And any increase in
latency between code execution and the first pivot within the network can be
crucial in an effective response.

Finally, perfect is the enemy of good. Trying to force a default-deny binary
whitelisting system on users is a recipe for conflict. Putting admins directly
in the path for whitelisting approval is often unscalable and breeds antagonism
towards the security staff. Social whitelisting is a huge boon to both user
convenience and overall security when deploying lockdown mode.
