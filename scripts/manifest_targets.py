#!/usr/bin/env python3
"""Print the promotion targets for a manifest, space separated."""
import sys

from common import load_manifest, targets_for_exposure

m = load_manifest(sys.argv[1])
print(" ".join(targets_for_exposure(m["exposure"], m["backend"]["mode"])))
