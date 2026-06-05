# How to install SentinelForge v1.5 on your computer

This guide is written for someone who does not live in the terminal every day.

## What SentinelForge does

SentinelForge checks a software project for security problems before you share or ship it.

Think of it like a safety inspector for an app:

- It looks for risky code.
- It looks for leaked passwords or secret keys.
- It checks whether known dangerous security problems show up.
- It gives your project a simple grade, like A+ or B.
- It creates reports you can read later.

## The finished package files

The installable package files are in this folder on the VPS:

```text
/root/sentinelforge/dist/
```

The main file to install is:

```text
sentinelforge-1.5.0-py3-none-any.whl
```

There is also a backup source package:

```text
sentinelforge-1.5.0.tar.gz
```

## Best beginner install method

The easiest clean install method is called `pipx`.

Plain English: `pipx` installs command-line apps without messing up the rest of your computer.

## Step 1: Get the package file onto your computer

Download or copy this file from the VPS to your computer:

```text
/root/sentinelforge/dist/sentinelforge-1.5.0-py3-none-any.whl
```

If you use `scp`, the command from your own computer will look like this:

```bash
scp root@72.61.237.239:/root/sentinelforge/dist/sentinelforge-1.5.0-py3-none-any.whl .
```

That puts the package file into the folder you are currently in on your computer.

## Step 2: Install pipx if you do not have it

### On Mac

If you have Homebrew:

```bash
brew install pipx
pipx ensurepath
```

Then close and reopen Terminal.

### On Windows

In PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
```

Then close and reopen PowerShell.

### On Linux

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
```

Then close and reopen Terminal.

## Step 3: Install SentinelForge

Run this from the same folder where the `.whl` file is:

```bash
pipx install ./sentinelforge-1.5.0-py3-none-any.whl
```

## Step 4: Check that it installed

Run:

```bash
sentinelforge --help
```

If you see commands like `scan`, `doctor`, `gate`, `init-policy`, `init-ci`, and `explain`, it worked.

## Step 5: Check optional security helper tools

Run:

```bash
sentinelforge doctor
```

It may say tools like Semgrep, Bandit, OSV Scanner, Trivy, or Gitleaks are missing.

That is okay. SentinelForge still works. Those tools just make scans stronger when installed.

## Step 6: Scan a project you own

Go into the project folder you want to check:

```bash
cd path/to/your/project
```

Then run:

```bash
sentinelforge scan --target . --mode static
```

Important: only scan software you own or are allowed to test.

## Step 7: Read the result

After a scan, SentinelForge prints a grade and creates reports.

The reports are usually here:

```text
reports/latest_report.md
reports/latest_report.json
reports/latest_report.html
```

Open the HTML file in a browser if you want the easiest report to read.

## Simple meaning of the grades

- A+ or A: very good, likely okay to ship.
- B: okay, but you should look at the warnings.
- C or lower: stop and fix things first.

## Useful commands

Create a starter security policy:

```bash
sentinelforge init-policy
```

Create GitHub Actions CI setup:

```bash
sentinelforge init-ci
```

Explain one finding in plain English:

```bash
sentinelforge explain --finding-id FINDING_ID --report reports/latest_report.json
```

Use a report as a release gate:

```bash
sentinelforge gate --report reports/latest_report.json --minimum-grade A
```

## If you need to uninstall it

```bash
pipx uninstall sentinelforge
```

## What was verified before calling this done

- The package built successfully.
- The wheel installed into a clean test environment.
- `sentinelforge --help` worked from the installed package.
- `sentinelforge doctor` worked from the installed package.
- The installed package reports version `1.5.0`.
- The full test suite passed.
- SentinelForge self-scan scored A+ with 98.75 / 100.
- The security gate passed with minimum grade A.
