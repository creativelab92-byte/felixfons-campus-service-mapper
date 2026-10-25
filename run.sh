#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 campus_mapper.py collect
