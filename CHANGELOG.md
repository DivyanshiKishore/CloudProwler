# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-27

### Added
- AWS S3 public access auditing
- IAM AdministratorAccess detection
- IAM privilege escalation checks
- EC2 IMDSv1 exposure detection
- Security Group exposure detection
- Dynamic environment risk scoring
- HTML security dashboard
- JSON report generation
- Rich CLI dashboard
- Offline demo mode
- Severity-based filtering
- Multi-region support
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