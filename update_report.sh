#!/bin/bash
# for automatic commits in report
git add .
git commit -m "update $1 in report"
git push
