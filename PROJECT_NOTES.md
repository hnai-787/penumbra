# Project Notes

## Source

Migrated from `air-university-cybersecurity-projects/projects/firewall-rule-engine-cpp`
(a separate academic-portfolio repo) into this workspace as an independent
project on 2026-09-07.

## Cleanup decisions

- The compiled `firewall.exe` present in the source folder was **not**
  copied — this workspace's `templates/project/project.gitignore` excludes
  build output, and the source repo's own `PROJECT_STANDARDS.md` already
  flagged it as something that shouldn't have been committed. Rebuild with
  `g++ src/main.cpp src/firewall.cpp -o firewall`.
- No other content changes were made — rules, packets, output, and
  screenshots are copied as-is.

## Assumptions

- `status: completed` in `project.yaml` reflects that this was a finished,
  submitted coursework assignment, not that it received a specific grade
  (no grade information exists in the source material).

## Remaining work

- None identified. This project was already in a clean, reviewable state
  in the source repo.
