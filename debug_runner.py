import subprocess
import sys

print("Starting debug runner...")
with open("debug.log", "w") as f:
    try:
        # Use the current python executable
        cmd = [sys.executable, "pipeline.py", "--scrape"]
        f.write(f"Running command: {cmd}\n")
        result = subprocess.run(cmd, capture_output=True, text=True)
        f.write("STDOUT:\n")
        f.write(result.stdout)
        f.write("\nSTDERR:\n")
        f.write(result.stderr)
        f.write(f"\nReturn Code: {result.returncode}\n")
    except Exception as e:
        f.write(f"EXECUTION ERROR: {e}")
print("Debug runner finished.")
