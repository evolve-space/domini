.PHONY: audit compile ci

compile:
	pip-compile requirements.in -o requirements.txt

audit:
	pip-audit -r requirements.txt

# Run as part of CI to catch known vulnerabilities in dependencies
ci: audit
