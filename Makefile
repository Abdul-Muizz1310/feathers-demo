.PHONY: run test

run:
	uv run uvicorn feathers_demo.main:app --reload

test:
	uv run pytest
