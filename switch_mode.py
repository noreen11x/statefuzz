"""Switch Kamailio between the secure and the misconfigured mode.

    python switch_mode.py normal    secure configuration
    python switch_mode.py buggy     credentials are not verified (misconfiguration)

It restarts only the Kamailio container with the chosen setting, then waits
a few seconds so bob can register again (Kamailio forgets him on restart).
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFINES = {"normal": "", "buggy": "-A WITH_AUTH_BUG -A WITH_STATE_BUG"}

if len(sys.argv) != 2 or sys.argv[1] not in DEFINES:
    print("Usage: python switch_mode.py normal|buggy")
    raise SystemExit(1)

mode = sys.argv[1]
with open(os.path.join(HERE, ".env"), "w") as f:
    f.write(f"KAMAILIO_DEFINES={DEFINES[mode]}\n")
with open(os.path.join(HERE, "server_mode.txt"), "w") as f:
    f.write(mode + "\n")

print(f"Restarting Kamailio in {mode} mode ...")
subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "kamailio"],
               cwd=HERE, check=True)
print("Waiting 8 seconds for bob to register again ...")
time.sleep(8)
print(f"Kamailio is in {mode} mode. Now run:  python rule_checker.py")
