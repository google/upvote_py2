#!/bin/bash
# Execute a shard of the set of Bazel tests.
#   Usage: ./run_tests.sh SHARD_INDEX TOTAL_SHARDS

set -ex

current_test_group=${1:-0}
total_test_groups=${2:-1}
all_tests=$(bazel query 'tests(//upvote/...) union tests(//common/...)')
num_tests=$(echo "${all_tests}" | wc -w)

group_size=$(echo "1 + ${num_tests} / ${total_test_groups}" | bc)
lower_bound=$(echo "${current_test_group} * ${group_size}" | bc)
upper_bound=$(echo "${lower_bound} + ${group_size}" | bc)

current_tests=$(
  echo "${all_tests}" |
  tr "\n" " " |
  python -c "print ' '.join(raw_input().split()[${lower_bound}:${upper_bound}])")

if [[ -n "${current_tests}" ]]; then
  eval "bazel test \
    --curses=no \
    --test_output=errors \
    --spawn_strategy=standalone \
    --test_strategy=standalone \
    ${current_tests}"
fi
