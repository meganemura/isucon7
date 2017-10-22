#!/bin/bash

for hostname in server1 server2; do
  scp /home/isucon/isubata/webapp/public/icons/$1 $hostname:/home/isucon/isubata/webapp/public/icons/
done
