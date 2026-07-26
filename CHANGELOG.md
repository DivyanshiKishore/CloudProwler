# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.0] - 2026-07-27

### Added

- Initial stable release of CloudProwler
- AWS cloud security misconfiguration auditing
- IAM security checks
- S3 exposure detection
- JSON report generation
- HTML security dashboard generation
- CLI-based scanning workflow
- GitHub Actions CI pipeline
- Automated pytest validation
- GitHub issue templates and security reporting workflow

### Documentation

- Added project README
- Added contribution guidelines
- Added security policy
- Added architecture and workflow diagrams

### Project Structure

- Modular scanner architecture
- Reporting module
- Asset documentation
- Docker support

### Changed
- Standardized finding schema across scanner modules.
- Improved report generation.
- Cleaned up unused code before public release.

### Fixed
- Fixed HTML report resource mapping.
- Removed duplicate JSON export function.
- Removed unused concurrent scanning implementation.
- Enabled region parameter support.