#!/usr/bin/env python3

CHANGE_THRESHOLD = 0.2

import sys
from pathlib import Path
import shutil
import subprocess

if len(sys.argv) >= 2 and sys.argv[1] == "-f":
    force = True
    sys.argv.pop(1)
else:
    force = False

if len(sys.argv) < 2:
    outdir = Path("../auto-placement/output")
else:
    outdir = Path(sys.argv[1])

if outdir.name == "output":
    # grab the latest run
    outdir = max(outdir.glob('out-*'))

blob = outdir / 'decoys.blob'
if not blob.exists():
    print("{} does not exist yet, waiting for output run to complete".format(blob))
    sys.exit(2)

decoys_txt = next(outdir.glob('*[0-9]-decoys.txt'))
decoys_dst = Path(decoys_txt.name)

if Path(decoys_dst).exists():
    print("Output already exists, aborting")
    sys.exit(1)

latest_txt = max(Path('.').glob("20*-decoys.txt"))
with latest_txt.open() as ltf:
    latest_count = sum(1 for l in ltf if l[0] != '#')

with decoys_txt.open() as dtf:
    new_count = sum(1 for l in dtf if l[0] != '#')

if not force and abs(new_count - latest_count)*2 / (new_count + latest_count) > 0.2:
    change_file = decoys_dst.with_suffix('.changed')
    if not change_file.exists():
        print("Not pushing decoy list: more than 20% change ({} -> {}). Rerun with -f to force update".format(latest_count, 
                                                                                      new_count), file=sys.stderr)
        change_file.touch()
    sys.exit(1)

print("{} -> {}".format(decoys_txt, decoys_dst))
shutil.copy(str(decoys_txt), str(decoys_dst))

datestr = "{}-{}".format(*decoys_txt.name.split('-')[:2])

blob = outdir / 'decoys.blob'

blob_dst = "{}-decoys.blob".format(datestr)

print("{} -> {}".format(blob, blob_dst))
shutil.copy(str(blob), blob_dst)

current_decoy = "current_decoys.blob"
print("{} -> {}".format(blob_dst, current_decoy))
shutil.copy(blob_dst, current_decoy)

subprocess.call(["git", "add", decoys_dst, blob_dst, current_decoy])
subprocess.call(["git", "commit", "-m", 
                 "Updated decoys based on {} run".format(datestr)])
