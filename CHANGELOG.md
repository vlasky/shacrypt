# Changelog

## [0.5.1] - 2026-01-29

### Added
- TypeScript type declarations (`index.d.ts`)

## [0.5.0] - 2026-01-28

### Changed
- **Breaking:** Minimum Node.js version is now 18.0.0
- Updated NAN to 2.25.0 for Node.js 25 compatibility
- Updated mocha to 11.3.0 and chai to 6.2.2
- Replaced `NODE_MODULE` with `NAN_MODULE_WORKER_ENABLED` for proper module registration
- Fixed null pointer subtraction warnings in sha256crypt.c and sha512crypt.c using `uintptr_t`

### Added
- Support for Node.js 25

## [0.4.0] - 2025-06-27

### Added
- New ES6 async/await compatible functions: `sha256cryptAsync()` and `sha512cryptAsync()`
- These functions return Promises and can be used with modern async/await syntax
- Full test coverage for the new async functions

### Changed
- Updated documentation to include examples of the new async/await API

## [0.3.0] - 2025-06-14

### Added
- Input validation and error handling to prevent crashes
- Support for Node.js 16-23

## [0.2.0] - 2019-12-16

### Added
- Asynchronous support through optional callback functions
- Windows build compatibility improvements
- Cross-platform portability enhancements

### Changed
- Updated nan to latest version 2.14.0 to make it work under Node.js v12
- Replaced endian.h with portable_endian.h for better cross-platform support

## Previous versions

See git history for older changes.