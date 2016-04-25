# python_scripts
Expanded Unix utilities 

root_getopt.py:  utility functions library

sgrep.py  'Super' grep:  Allows field specific grep  
  * cat file | sgrep.py 1 textstring  2 5lt
  
This will grep match only if 'textstring' is in field 1, NOT in any other field
AND  field 2 has a numeric value less than 5.


Download test.data and english_currency examples:  
cat test.data | python ~/bin/sgrep.py OR  3 2lt 2 ':4=~' 3n F4gt 2n Walking 1n english_currency=f2 -c 1

OR logic on following compares:  
  * field 3 has numeric value < 2  
  * field 2 has regex compare =~ ':4'  
  * field -3 numerically greater than field 4  
  * field -2 is exactly 'Walking'  
  * field -1 is any value from the second field of file english_currency ( GBP | USD | CAN )

lastly, -c 1 shows which fields matched any of these 5 criteria.  
Remove this flag and you will get only lines that match the above criteria.
