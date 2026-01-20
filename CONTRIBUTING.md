# Contributing to systemd-netlogd

Thank you for your interest in contributing to systemd-netlogd! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)

## Code of Conduct

This project follows the systemd Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- C compiler (GCC or Clang)
- systemd development libraries (>= 230)
- meson build system (>= 0.51)
- pkg-config
- gperf
- libcap development libraries
- OpenSSL development libraries (>= 1.1.0)
- cmocka (for testing)

### Setting Up Development Environment

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR-USERNAME/systemd-netlogd.git
   cd systemd-netlogd
   ```

2. **Add Upstream Remote**
   ```bash
   git remote add upstream https://github.com/systemd/systemd-netlogd.git
   ```

3. **Install Dependencies**

   Fedora/RHEL/CentOS:
   ```bash
   sudo dnf install gcc meson pkg-config gperf libcap-devel systemd-devel \
                    openssl-devel libcmocka-devel python3-sphinx
   ```

   Debian/Ubuntu:
   ```bash
   sudo apt install build-essential meson pkg-config gperf libcap-dev \
                    libsystemd-dev libssl-dev libcmocka-dev python3-sphinx
   ```

4. **Build the Project**
   ```bash
   meson setup build
   meson compile -C build
   ```

5. **Run Tests**
   ```bash
   meson test -C build -v
   ```

## Development Setup

### Build Options

Configure the build with custom options:

```bash
# Debug build
meson setup build --buildtype=debug

# Release build with optimizations
meson setup build --buildtype=release

# Custom installation prefix
meson setup build --prefix=/usr

# Disable OpenSSL (no TLS/DTLS support)
meson setup build -Dopenssl=disabled
```

### Cleaning Build Directory

```bash
rm -rf build/
meson setup build
```

## Making Changes

### Before You Start

1. **Check Existing Issues**: Look for existing issues or discussions related to your change
2. **Create an Issue**: For significant changes, create an issue first to discuss the approach
3. **Create a Branch**: Use descriptive branch names

```bash
git checkout -b feature/add-compression-support
git checkout -b fix/connection-retry-bug
git checkout -b docs/improve-tls-examples
```

### Types of Contributions

We welcome:

- **Bug fixes**: Fix incorrect behavior or crashes
- **Features**: Add new functionality (discuss in issue first)
- **Documentation**: Improve or add documentation
- **Tests**: Add test coverage
- **Performance**: Optimize existing code
- **Code cleanup**: Refactoring without behavior changes

## Coding Standards

### Style Guidelines

This project follows systemd coding conventions:

1. **Indentation**: 8 spaces (no tabs)
2. **Line Length**: Maximum 109 characters
3. **Braces**: K&R style
   ```c
   if (condition) {
           /* code */
   } else {
           /* code */
   }
   ```

4. **Variable Names**: snake_case
   ```c
   int connection_retry_count;
   Manager *manager;
   ```

5. **Function Names**: snake_case
   ```c
   int manager_connect(Manager *m);
   void tls_disconnect(TLSManager *m);
   ```

6. **Constants**: UPPER_CASE
   ```c
   #define DEFAULT_CONNECTION_RETRY_USEC   (30 * USEC_PER_SEC)
   ```

### Code Organization

1. **Header Guards**: Use `#pragma once`
2. **Includes Order**:
   - System headers
   - Library headers
   - Local headers

   ```c
   #include <stdio.h>
   #include <systemd/sd-journal.h>
   #include "netlog-manager.h"
   ```

3. **SPDX License**: Every file must start with:
   ```c
   /* SPDX-License-Identifier: LGPL-2.1-or-later */
   ```

4. **Function Documentation**: Document complex functions
   ```c
   /* Connects to the remote syslog server
    * Returns: 0 on success, negative errno on failure */
   int manager_connect(Manager *m);
   ```

### Error Handling

1. **Use negative errno values** for errors
   ```c
   if (fd < 0)
           return log_error_errno(errno, "Failed to open socket: %m");
   ```

2. **Use cleanup macros** for resource management
   ```c
   _cleanup_free_ char *buffer = NULL;
   _cleanup_close_ int fd = -1;
   ```

3. **Check all allocations**
   ```c
   m = new(Manager, 1);
   if (!m)
           return log_oom();
   ```

### Memory Management

1. **Use cleanup functions** when possible
2. **Initialize pointers** to NULL
3. **Use TAKE_PTR()** for ownership transfer
4. **Free resources** in reverse allocation order

### Logging

Use appropriate log levels:

```c
log_debug("Connection attempt to %s", address);
log_info("Network configuration changed");
log_warning("Certificate validation disabled");
log_error("Failed to connect to remote server");
```

## Testing

### Running Tests

```bash
# Run all tests
meson test -C build -v

# Run specific test
meson test -C build test-protocol -v

# Run tests with address sanitizer
meson setup build -Db_sanitize=address
meson test -C build -v
```

### Writing Tests

1. **Use cmocka** framework
2. **Test file naming**: `test-<module>.c`
3. **Test function naming**: `test_<feature>()`

Example test structure:

```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_my_feature(void **state) {
        int result = my_function();
        assert_int_equal(result, EXPECTED_VALUE);
}

int main(void) {
        const struct CMUnitTest tests[] = {
                cmocka_unit_test(test_my_feature),
        };
        return cmocka_run_group_tests(tests, NULL, NULL);
}
```

### Test Coverage

Aim for:
- All new functions should have tests
- Edge cases and error conditions
- Protocol compliance (RFC 5424, RFC 3339)

## Submitting Changes

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>: <short description>

<detailed description>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Build system, dependencies

Example:

```
feat: Add exponential backoff for connection retries

Implements exponential backoff starting at 1s and capping at 5min
to better handle temporary network outages. This reduces load on
failing servers while maintaining responsiveness.

Fixes #42
```

### Commit Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated if needed
- [ ] Commit message is clear and descriptive
- [ ] No compiler warnings
- [ ] License headers present

### Submitting Pull Requests

1. **Update your branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push to your fork**
   ```bash
   git push origin feature/my-feature
   ```

3. **Create Pull Request**
   - Use a clear, descriptive title
   - Reference related issues
   - Describe what changed and why
   - Include test results if applicable

4. **PR Template**
   ```markdown
   ## Description
   Brief description of changes

   ## Motivation
   Why is this change needed?

   ## Changes
   - List of changes

   ## Testing
   How was this tested?

   ## Checklist
   - [ ] Tests pass
   - [ ] Documentation updated
   - [ ] Follows coding standards
   ```

## Review Process

### What to Expect

1. **Initial Review**: Maintainers review within a few days
2. **Feedback**: Suggestions for improvements
3. **Iteration**: Make requested changes
4. **Approval**: At least one maintainer approval required
5. **Merge**: Maintainer will merge approved PRs

### Responding to Feedback

- Be open to suggestions
- Ask for clarification if needed
- Make requested changes in new commits (don't force push during review)
- Mark conversations as resolved when addressed

### Review Criteria

Reviewers check for:
- Correctness and functionality
- Code quality and style
- Test coverage
- Documentation
- Performance implications
- Security considerations
- Backward compatibility

## Development Tips

### Debugging

```bash
# Run with debug logging
SYSTEMD_LOG_LEVEL=debug ./build/systemd-netlogd

# Use GDB
gdb --args ./build/systemd-netlogd

# Check for memory leaks
valgrind --leak-check=full ./build/systemd-netlogd
```

### Static Analysis

```bash
# Enable compiler warnings
meson setup build -Dwarning_level=3

# Use clang-tidy
clang-tidy src/netlog/*.c
```

### Performance Profiling

```bash
# Profile with perf
perf record -g ./build/systemd-netlogd
perf report
```

## Resources

- [systemd Coding Style](https://systemd.io/CODING_STYLE/)
- [RFC 5424](https://tools.ietf.org/html/rfc5424) - Syslog Protocol
- [RFC 3339](https://tools.ietf.org/html/rfc3339) - Date and Time on the Internet
- [systemd Journal API](https://www.freedesktop.org/software/systemd/man/sd-journal.html)

## Getting Help

- **Issues**: Create an issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **IRC**: #systemd on irc.libera.chat (for systemd-related questions)

## Recognition

Contributors are listed in the project's commit history. Significant contributions will be acknowledged in release notes.

---

Thank you for contributing to systemd-netlogd!
