#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <t> <c> <i>"
  exit 1
fi

t=$1
c=$2
i=$3

for j in {1..5}
do
  python3 HSCFuzz.py -t "$t" -c "$c" -i "$i" -o outputs

  # Extract the variable x from the filename
  for file in outputs/leaks/sim_input/id_*.si
  do
    # Extract the variable x using parameter expansion
    x=$(basename "$file" | cut -d'_' -f2 | cut -d'.' -f1)

    # Check if x is a valid number
    if [[ "$x" =~ ^[0-9]+$ ]]; then
      # Increment x by 1
      x_plus_one=$((x + 1))

      # Save the incremented value
      echo "t: $t, c: $c, i: $i, x: $x_plus_one" >> variables.txt

    else
      echo "Invalid x value: $x" >> variables.txt
    fi
  done

  # Clear the outputs directory
  rm -rf outputs/*

done
echo "----------------------" >> variables.txt