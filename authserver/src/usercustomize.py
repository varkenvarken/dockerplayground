import os

coverage = "coverage module not imported"
try:
    import coverage
    coverage.process_startup()
    var = 'COVERAGE_PROCESS_START'
    cps = os.environ[var] if var in os.environ else f"{var} not defined"
    if cps == "":
        cps = f"{var} is empty"
    coverage = f"coverage imported, {cps}"
except ModuleNotFoundError:
    pass
