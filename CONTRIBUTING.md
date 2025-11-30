# Contributing to KeyVault CA

Thank you for taking the time to contribute! This guide captures the expectations for raising issues, proposing changes, and collaborating with the maintainers.

## Ways to contribute
- **Report bugs or request features** by opening a GitHub issue that clearly describes the scenario and the expected behavior.
- **Improve docs** by refining explanations, adding walkthroughs, or fixing typos.
- **Submit code changes** that fix bugs, improve reliability, or add well-scoped features aligned with the roadmap.

Please discuss larger changes in an issue first to ensure alignment with project goals. If you used AI to assist in writing code, please disclose this in your pull request description.

## Getting started
1. Install the prerequisites listed in `Readme.md` (Azure CLI, .NET 8 SDK, etc.).
2. Fork the repository and create a feature branch off `main`.
3. Run `dotnet restore`, `dotnet build`, and `dotnet test` locally before submitting your work.

## Development workflow
- Prefer small, focused pull requests with descriptive titles.
- Follow existing coding styles; use `dotnet format` where appropriate.
- Add or update unit tests alongside code changes. When tests are not feasible, explain the reasoning in the PR description.
- Update documentation whenever behavior changes or new workflows are introduced.

## Commit and PR guidelines
- Use conventional, informative commit messages (e.g., `fix: handle empty CSR inputs`).
- Reference related issues in the PR body using `Fixes #123` where applicable.
- Ensure the PR template checklist is completed before requesting a review.
- All CI checks must pass before merge. Maintainers may request additional tests or documentation.

## Code of conduct
By participating, you agree to foster a friendly, safe environment for everyone. Be respectful, assume positive intent, and collaborate constructively.

We appreciate your help in making KeyVault CA better!
