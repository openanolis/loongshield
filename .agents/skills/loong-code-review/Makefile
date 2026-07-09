SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

.PHONY: test check

test:
	@tests/test_resolve_target.sh
	@tests/test_build_pass_prompt.sh
	@tests/test_assemble_review.sh

check: test
