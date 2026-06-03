# SentinelForge First-Customer Outreach Plan

Goal: get the first Security Baseline Review customer.

## Best first offer

Before you ship AI-written or client code, get a plain-English SentinelForge Security Baseline Review.

Keep public pricing off the repo. Discuss scope and payment privately after the person shows interest.

## Best first customers

1. Freelance web developers
2. AI app builders
3. AI automation consultants
4. Small agencies
5. Solo SaaS founders

## Where to look first on GitHub

Look for public repos that are actively building MVPs or AI apps and appear to be maintained by solo builders or small teams.

Useful GitHub searches:

```text
"openai" "next.js" "supabase" stars:<50 pushed:>2025-01-01
"anthropic" "fastapi" stars:<50 pushed:>2025-01-01
"langchain" "streamlit" stars:<50 pushed:>2025-01-01
"ai agent" "api key" stars:<100 pushed:>2025-01-01
"MVP" "SaaS" stars:<100 pushed:>2025-01-01
"launch" "nextjs" "stripe" stars:<100 pushed:>2025-01-01
"client" "website" "freelance" stars:<100 pushed:>2025-01-01
```

Do not spam random repos.

Good lead signs:

- The repo has recent commits.
- The README describes an app or product, not just a tutorial.
- The owner looks like a solo builder, freelancer, or small team.
- The app uses APIs, auth, payments, AI, databases, or webhooks.
- There are open issues asking about launch, deployment, security, API keys, auth, or production readiness.

Bad lead signs:

- Big company repo
- Security-sensitive enterprise repo
- Student homework repo
- Abandoned repo
- Repo with strict no-solicitation rules
- Repo where outreach would look like fearmongering

## Soft outreach message

Use this when contacting a builder directly through a public channel where outreach is welcome:

```text
Hey — I found your project while looking for small apps that might benefit from lightweight pre-launch security checks.

I built SentinelForge, a local-first security release checker that scans for common issues like leaked secrets, risky API routes, outdated dependencies, unsafe AI app patterns, and Docker/config problems. It gives a plain-English report and a release-readiness grade.

I’m offering a few beta Security Baseline Reviews while I validate the product. No pressure at all — would a plain-English pre-launch security report be useful for this project?
```

## GitHub issue comment rule

Avoid posting sales comments directly on unrelated issues.

Only comment if:

- The issue is explicitly about security, launch readiness, leaked keys, auth, dependencies, CI, or deployment checks.
- Your comment is helpful even if they never pay.
- You disclose that you are the builder of SentinelForge.

Helpful issue comment example:

```text
This looks like the kind of risk a pre-launch security checklist can help catch early: secrets, dependency versions, auth paths, and config defaults.

I’m building SentinelForge, a local-first security release checker for small apps and AI-built projects. The free CLI may help you run a quick first-pass check locally. If useful, the repo is here: <repo-url>

No scanner guarantees security, but it can help catch common mistakes before launch.
```

## First 20-lead workflow

For each lead:

1. Record repo URL.
2. Record owner/contact path.
3. Note why they might care.
4. Do not scan their code unless it is clearly allowed and safe.
5. Send one respectful message only where appropriate.
6. Track response.
7. If no response, move on.

## Lead tracker columns

Use `docs/LEADS.md` with this format:

```text
| Status | Repo/User | Why relevant | Contact path | Message sent? | Response | Next step |
```

Statuses:

- Candidate
- Contacted
- Interested
- Not interested
- Customer
- Skip

## First offer script after interest

```text
Awesome. For the beta mini-review, I’ll run SentinelForge on the project you authorize, review the results, and give you a plain-English summary with the top risks and what to fix first.

Please do not send secrets or private credentials. If the repo is private, we can work out a safe way to review only what you authorize.
```
