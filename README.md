<!-- mdformat off(GitHub header) -->
Upvote
[![Build Status](https://travis-ci.com/google/upvote.svg?token=s6uTQfwvqCpdWthaypND&branch=master)](https://travis-ci.com/google/upvote)
======
<!-- mdformat on -->

<p align="center">
  <a href="#upvote--">
    <img src="upvote/gae/modules/upvote_app/frontend/web_ui/static/upvote_logo.svg" alt="Upvote Icon" width=128 />
  </a>
</p>

Upvote is multi-platform binary whitelisting solution. It provides both a sync
server and management interface for binary enforcement clients. Upvote currently
supports [Santa](https://github.com/google/santa) on macOS and
[Bit9](https://www.carbonblack.com/products/cb-protection/) (now known as Carbon
Black Protection) on Windows.

## Features

-   **First-party sync server for Santa**
    -   Written in coordination with Santa's development team
-   **User-oriented Policy Creation**
    -   Apply policies to users instead of hosts
    -   No migration necessary when users get new hosts
-   **BigQuery streaming**
    -   Fast, easy, and scalable relational access to Santa and Bit9 execution
        data
-   **Bundled Voting for .app bundles on macOS**
    -   Easily create policy for an entire bundle at once
-   **VirusTotal Integration**
    -   View VirusTotal results directly in the detail page

## Screenshot

<kbd> <img src="./docs/images/screenshot_voting.png" alt="Voting page screenshot"> </kbd>

## Setup

See the [docs page](setup.md) for full instructions.

## Docs

Documentation is currently located in the top-level [docs](./docs/) directory.

## Contributing

We are current working hard to get Upvote ready for external contributions.
However, at this time, we do not have the necessary approvals to do so.

In the meantime, please feel free to file GitHub issues or post in our Google
Group, [upvote-discuss](https://groups.google.com/forum/#!forum/upvote-discuss),
with any comments, bugs, or feature requests.

## Contributors

Core Contributors: [Chief](https://github.com/chief8192),
[Matthew](https://github.com/msuozzo)

Special thanks to [Danny](https://github.com/danielloera),
[Haru](https://github.com/haruphoenix), [Maxim](https://github.com/maximermilov)

And to the Santa team: [Russell](https://github.com/russellhancox),
[Tom](https://github.com/tburgin), [Ed](https://github.com/eigerman),
[Phillip](https://github.com/nguyen-phillip)

## Disclaimer

This is not an official Google product.
