"""Entry point: python -m lab --check | --smoke | --run."""
from .runtime import main

if __name__ == "__main__":
    raise SystemExit(main())
