#!/bin/bash

lcov --capture -b linux-3.9.11 --directory linux-3.9.11 --output-file coverge.info
mkdir -p gcov_html
genhtml coverge.info  --output-directory gcov_html/

