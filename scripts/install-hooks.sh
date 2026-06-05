#!/bin/bash
# install-hooks.sh
# Installs Git hooks for Nauthilus development
#
# Usage:
#   ./scripts/install-hooks.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOOKS_DIR="${PROJECT_ROOT}/.git/hooks"

echo "Installing Git hooks..."

# Create pre-commit hook
cat > "${HOOKS_DIR}/pre-commit" << 'HOOKEOF'
#!/bin/bash
# Pre-commit hook for Nauthilus
# This hook validates mandatory policy/prompt guardrails and staged Go HTML templates before allowing a commit.
#
# Installation:
#   Run: ./scripts/install-hooks.sh
#
# To bypass this hook temporarily (not recommended):
#   git commit --no-verify

set -e

# Get the root directory of the git repository
GIT_ROOT=$(git rev-parse --show-toplevel)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Running pre-commit checks...${NC}"

# Keep AGENTS.md aligned with .junie/guidelines.md even if IDE formatting touched AGENTS.md.
cd "$GIT_ROOT"
if ! make sync-prompts-check >/dev/null 2>&1; then
    echo -e "${YELLOW}AGENTS.md is out of sync; auto-syncing from .junie/guidelines.md...${NC}"
    make sync-prompts
    git add AGENTS.md
fi

# Ensure mandatory prompt and policy guardrails are respected.
make sync-prompts-check
make policy-check

# Check if any template files are staged for commit
STAGED_TEMPLATES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '^static/templates/.*\.html$' || true)

if [ -n "$STAGED_TEMPLATES" ]; then
    echo -e "${YELLOW}Validating staged HTML templates...${NC}"

    # Validate only the staged template files
    VALIDATION_FAILED=0
    for template in $STAGED_TEMPLATES; do
        if [ -f "$template" ]; then
            if ! go run scripts/validate-templates.go "$template" 2>&1; then
                VALIDATION_FAILED=1
            fi
        fi
    done

    if [ $VALIDATION_FAILED -ne 0 ]; then
        echo ""
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  COMMIT BLOCKED: Template validation failed!               ║${NC}"
        echo -e "${RED}║                                                            ║${NC}"
        echo -e "${RED}║  Please fix the template errors above before committing.   ║${NC}"
        echo -e "${RED}║  This prevents corrupted Go templates from being committed.║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        exit 1
    fi

    echo -e "${GREEN}All staged templates are valid.${NC}"
else
    echo -e "${GREEN}No template files staged for commit.${NC}"
fi

echo -e "${GREEN}Pre-commit checks passed.${NC}"
exit 0
HOOKEOF

chmod +x "${HOOKS_DIR}/pre-commit"

# Create pre-push hook
cat > "${HOOKS_DIR}/pre-push" << 'HOOKEOF'
#!/bin/bash
# Pre-push hook for Nauthilus
# This hook runs govulncheck before publishing main or version tags.
#
# Installation:
#   Run: ./scripts/install-hooks.sh
#
# To bypass this hook temporarily (not recommended):
#   git push --no-verify

set -e

GIT_ROOT=$(git rev-parse --show-toplevel)

exec "${GIT_ROOT}/scripts/pre-push-govulncheck.sh" "$@"
HOOKEOF

chmod +x "${HOOKS_DIR}/pre-push"
chmod +x "${PROJECT_ROOT}/scripts/pre-push-govulncheck.sh"

echo "✓ Git hooks installed successfully"
echo ""
echo "The following hooks are now active:"
echo "  - pre-commit: Validates policy/prompt guardrails and staged Go HTML templates"
echo "  - pre-push: Runs govulncheck before pushing main or version tags"
echo ""
echo "To manually validate all templates, run:"
echo "  ./scripts/validate-templates.sh"
echo ""
echo "To manually validate release-sensitive pushes, run:"
echo "  make release-guardrails"
