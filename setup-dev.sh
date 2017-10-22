#!/bin/bash -x
export MYSQL_HOST=127.0.0.1
cd webapp/ruby
docker-compose down
docker-compose up -d
cd ../..
# wait mysql
sleep 10
db/init.sh
