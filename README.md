# python_scripts
Expanded Unix utilities 

root_getopt.py:  utility functions library

sgrep.py  'Super' grep:  Allows field specific grep
  cat file | sgrep.py 1 textstring  2 5lt
  
This will grep match only if 'textstring' is in field 1, NOT in any other field
AND  field 2 has a numeric value less than 5.
