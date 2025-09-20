# PostgreSQL OAuth Extension

This extension (`pg_oauth`) provides OAuth token validation capabilities for PostgreSQL.

## Overview

The extension implements an OAuth validator module that can validate JWT tokens for authentication and authorization in PostgreSQL. It integrates with PostgreSQL's authentication system to enable OAuth-based access control.

## Dependencies

- `libjwt` - JWT library for token parsing and validation
- `libcurl` - HTTP client library for fetching OAuth provider metadata
- `jwt-cpp` - C++ JWT library (included as submodule)

## Components

- `pg_oauth.cpp` - Main extension module with validator callbacks
- `http_client.cpp/h` - HTTP client implementation for OAuth provider communication
- `meson.build` - Build configuration using Meson build system

## Build Requirements

- C++23 compiler support
- PostgreSQL development headers
- libjwt and libcurl development packages

## Scope

**IMPORTANT**: All development work should be confined to the `contrib/pg_oauth/` directory only. Do not modify files outside this folder.

## Build and Testing

- Build directory: `build/` (top-level)
- Use `ninja` in the build directory to test the build of the extension

## Current Status

The extension provides a basic OAuth validator framework with placeholder implementations for Google and Azure OAuth providers.