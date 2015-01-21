#!/bin/sh


source /home/yportnova/devops-venv/bin/activate
python fuelweb_test/run_tests.py -q --nologcapture --with-xunit --group=baremetal
