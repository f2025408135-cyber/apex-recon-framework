# Contributing to the APEX RECON FRAMEWORK

The **APEX RECON FRAMEWORK** is an elite, continually evolving methodology optimized for modern Application Security Research. Contributions to this repository are expected to adhere to a strict standard of technical rigor and operational utility.

## Submission Protocols

### 1. Architectural Enhancements
If you have developed a new recon methodology, a new AI-augmented prompt, or an optimization to an existing phase (e.g., a better way to scrape JavaScript maps or an updated GraphQL query):
* Open an issue outlining the operational deficiency in the current methodology and precisely how the proposed architectural change mitigates it.
* Ensure the new step explicitly answers the question: *"How does this help find broken developer assumptions?"*

### 2. Updating Tool Syntax
The security tooling landscape evolves rapidly. If a command listed in Phase 1-6 is deprecated or has been superseded by a significantly more efficient tool (e.g., a better alternative to `kiterunner` or `ffuf`):
* Submit a Pull Request directly.
* Include benchmark evidence in your PR description demonstrating the efficiency or coverage gain.

### 3. Pull Request Standards
1. Branch from `main` in your forked repository.
2. Guarantee that any proposed methodology strictly follows the existing Markdown structure.
3. Language must remain formal, authoritative, and highly technical.
4. Submit the pull request for architectural review.

## Code of Conduct
Participation in this project is subject to strict professional standards. Unprofessional behavior will result in immediate termination of contribution privileges.