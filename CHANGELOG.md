<!--
SPDX-FileCopyrightText: Copyright (C) 2024-2025 Marek Küthe <m.k@mk16.de>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Changelog

## Release 1.0.8

- Add FreeBSD support
- Add Capsicum sandboxing support
- Removal of an incorrect compiler warning
- Catch all errors, even the highly unlikely ones.
- Use functions with bounds checking

## Release 1.0.7

- Remove potentially bug-suppressing flags

## Release 1.0.6

- Improvement of landlock sandboxing
- Validation of the return value of the POSIX dup function
- Improvement of error messages
- Prevent routing of IPv6 link-local addresses
- Fix path to license file
- Correction of the copyright date
- Improve performance
- Improve security
- Improve type safety

## Release 1.0.5

- Adding capability management on Linux for improved security
- Add a seccomp filter to prevent unwanted syscalls
- Add landlock to restrict access rights

## Release 1.0.4

- Fixing an error that could lead to buffer invalidation
- Use another send function so that a complete response is always sent.
- Various minor performance improvements
- Use of the new Boost process library, if available, compatibility with boost88+

## Release 1.0.3

- Various minor performance improvements
- Set the ndebug flag in release builds to disable asserts and thus improve speed

## Release 1.0.2

- When handling NDP requests with a hop limit of 0, a response is no longer sent - previously a response was sent.

## Release 1.0.1

- Various minor performance improvements

## Release 1.0.0

- Initial release
