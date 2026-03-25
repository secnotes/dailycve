# Repository Maintenance Log

## Git History Cleanup - 2026-03-25

Performed major Git history cleanup to remove large binary files that were bloating the repository:
- Removed daily CVE ZIP files from Git history
- Reduced repository size from 367MB to 20MB
- Improved clone and fetch performance significantly

Note: This operation rewrote Git history. All contributors should re-clone the repository.
