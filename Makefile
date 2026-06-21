.PHONY: audit compile

compile:
	pip-compile requirements.in -o requirements.txt

audit:
	pip-audit -r requirements.txt
