## Application Control System Basics

An "application control system" is a piece of software that controls what can
run on a computer. It's used to prevent malware or other undesirable
applications from running on a host.

Binary whitelisting refers to the practice of explicitly allowing software at
the binary level. It often is referred to in conjunction with the policy
practice of permitting _only_ those binaries which are explicitly whitelisted.
In Upvote, we refer to this mode as "lockdown" and the more permissive mode
(allow all binaries _except_ those that have been explicitly blacklisted) as
"monitor". The notable benefit of "lockdown" mode is that it's one of the most
reliable means of preventing execution of previously-unknown malware i.e.
0-days.

Application control systems are often broken up into two pieces:

-   The agent (or client) software on the host that is in charge of enforcing
    policy and preventing execution
-   The policy server which is in charge of storing and updating the list of
    software the agents are permitted to execute.

### Upvote

Upvote is an implementation of an application control policy server and supports
the Santa and Bit9 agents for macOS and Windows, respectively. Upvote supports
both locally-scoped policies (e.g. "binary A is permitted to run on host H") as
well as globally-scoped ones (e.g. "binary B is permitted to run on _all_
hosts").

#### Social Voting

One differentiator of Upvote is that, unlike other application control solutions
where the execution policy is centrally managed, normal users may be permitted
to participate in the creation of policy through so-called "social voting". In
this process, users may vote on and share the software they're trying to run
and, once a threshold is reached, they get it whitelisted on their machine(s).

In distributing some of the policy-creation load away from administrators,
Upvote facilitates deployment of the more strict "lockdown" mode in
organizations with few administrators or those with fleets too large for manual
administration.

To reduce the impact of uninformed or malicious social voting, the intent is to
set a low voting threshold for local rule creation but a high voting threshold
for global rule creation. This limits the potential spread of the malicious
execution to the subset of infected users but keeps the fleet at large safe.

For a discussion on the security tradeoffs of this system, see the [security
section](security.md) of the docs.
