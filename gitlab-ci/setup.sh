#!/bin/bash

echo "preparation script"

pwd

uci set ieee1905.ieee1905.map_plugin="1"
uci commit ieee1905

cp -r ./test/files/etc/* /etc/
cp -r ./schemas/ubus/* /usr/share/rpcd/schemas
cp ./gitlab-ci/iopsys-supervisord.conf /etc/supervisor/conf.d/

ls /etc/config/
ls /usr/share/rpcd/schemas/
ls /etc/supervisor/conf.d/
