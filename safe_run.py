import sys
import traceback

with open("safe_run.log", "w") as f:
    sys.stdout = f
    sys.stderr = f
    print("Starting safe execution...")
    try:
        # Manually handle args for pipeline
        sys.argv = ["pipeline.py", "--scrape"]
        import pipeline
        # If pipeline.py has if __name__ == main logic, we might need to call main explicitly
        # But wait, importing it doesn't run main.
        # My pipeline.py now has logging setup in __name__ block.
        # I should just run main().
        pipeline.main()
    except Exception:
        traceback.print_exc()
