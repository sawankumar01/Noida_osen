# Startup Trust Score

A GitHub Actions-based startup website checker. Submit an issue with the
`Check a startup` form; the `check` label starts the workflow and the results
are posted as an issue comment. The app runs entirely in GitHub Actions and
uses only Node.js 20 built-ins.

## Trust score

The score is a weighted average, rounded to the nearest integer:

| Signal | Weight |
|---|---:|
| Domain age | 30% |
| Wayback history | 20% |
| HTTPS and reachability | 20% |
| Homepage/model analysis | 30% |

Scores of 80–100 mean strong indicators, 60–79 generally positive, 40–59
caution, and 0–39 high-risk indicators. A missing signal uses a neutral 50/100
and is called out in the report, so outages do not silently appear as negative
evidence. This is an automated screening, not proof of legitimacy or fraud.

## Enablement

GitHub discovers issue forms and Actions workflows only in the repository-root
`.github` directory. The issue form and workflow therefore live there; the
checker implementation and tests are under `Project`. Ensure GitHub Models is
available to the repository; the workflow requests only `models: read` and
uses the provided `GITHUB_TOKEN`.

## Local validation

Run tests with Node.js 20:

```sh
node --test Project/scripts/check.test.js
```
