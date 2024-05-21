<p align="center">
<a href="https://dust-ids.github.io"><img src="https://raw.githubusercontent.com/dust-ids/dust-ids.github.io/master/docs/images/logo_color.png" height="100px"/></a>
 </p>
<h1 align="center">DustIDS</h1>
<div align="center">
 <strong>
    The Lean IDS
 </strong>
</div>
<br/>

[Website](https://dust-ids.github.io)

`dust-ids` is a ... TODO

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [What's New?](#whats-new)
    - [Version 2.0.0](#version-200)
- [About](#about)
- [FAQ](#faq)
- [Features](#features)
- [Quick Bootstrapping](#quick-bootstrapping)
- [How to Contribute](#how-to-contribute)
  - [Versioning](#versioning)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## What's New?

#### Version 2.0.0

What's new in Version 2.0?

- [x] Upgrade to Clap 4.x
- [x] Shell Completion
- [x] Merge AppConfig with Clap/Cli arguments
- [x] use ConfigBuilder instead of Config
- [x] rustfmt update
- [x] Github release action

Planned for a 2.x release

- [x] Journald/Syslog as features
- [x] Fix CI/CD actions and Docker image

## About

`dust-ids` is an empty Rust CLI application with libraries, and few defaults. The goal is to help you bootstrap your next CLI project as quickly as possible while ensuring you make use of the best tools and best-practices that are available today.

There is no configuration required (though we recommend you check all the possible configurations possible). An empty clone will compile, and has a few sample commands. You can start coding right away!

## FAQ

For the Full FAQ, check the [website](https://dust-ids.github.io/#faq)

## Features

- [Clap](https://github.com/clap-rs/clap) for Command Line Argument parsing.
- Error Chaining with [Failure](https://github.com/rust-lang-nursery/failure).
- Configuration management with [config-rs](https://github.com/mehcode/config-rs).
- Multi-Drain, async Logging with [slog](https://github.com/slog-rs/slog).
- Static binaries with [rust-musl-builder](https://github.com/emk/rust-musl-builder).
- CI/CD through Github actions.
- Code Coverage, Justfile, etc..
- MIT License.

## Quick Bootstrapping

`dust-ids` should compile and run as is. You just need to clone the repository. A `cargo-generate` template is also [available](https://github.com/dust-ids/dust-ids-generate). For a more detailed introduction, check the [Getting Started](https://dust-ids.github.io/#getting-started) guide.

## How to Contribute

Details on how to contribute can be found in the [CONTRIBUTING.md](.github/CONTRIBUTING.md) file.

### Versioning

Rust Starter stricltly adheres to the [SemVer](https://semver.org/) Semantic Versioning.

## License

`dust-ids` is licensed under the MIT license. Please read the [LICENSE](LICENSE) file in this repository for more information.
