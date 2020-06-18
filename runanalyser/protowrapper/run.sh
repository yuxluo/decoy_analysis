#!/bin/bash
for file in ../list/*.txt; do
  echo "${file}"
  python3  main.py -k prod.apr-11-2017.pubkey -d ${file} -a asn.csv -g 2
done