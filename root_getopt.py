#!/usr/bin/python2.4

# Additional argument parsing and shared functions
# Jroot 11/2013

import sys
import re
import time
import os
import collections
import socket

pwd = os.getcwd()
homedir = os.path.expanduser('~')
DATADIR = homedir + '/data/'


WHITELIST = {'and': 1, 'a': 1, 'from': 1, 'for': 1, '&': 1, 'i': 1, 'of': 1, '+': 1, 'de': 1, '-': 1, '1': 1, 'to': 1, 'in': 1, 'the': 1, 'with': 1, 'by': 1, '_': 1, '/':1, 'on':1, 'is':1}
isdomain = re.compile('([^/]*)/*(.*)')   # pulls off domain:  Note the pathfile portion will be missing initial '/'; so does not fail on root urls
ispath =re.compile('(.*)\/([^/]*$)')  # splits file portion into path and not path
ispath = re.compile('\/*(.*)\/([^/]*$)')
isquery = re.compile('([^?]*\?*)([^=]*=*)(.*)')  # pulls of querystring, preserves parameter keyword if it exists


ishost = re.compile('([^/:]*):*[0-9]*\/*(.*)')  # strip ports!, pulls of host in [0], gracefully fails
isurl = re.compile('^https*:..([^/]*/)(.*)')
isbadip=re.compile('([0-9%\.\*]*%20)(.*)$') # corrupted IP/domain, legacy EDB data had 3.3.3.3 domainname.com  for some reason
isip = re.compile('[0-9 ]{1,3}\.[0-9 ]{1,3}\.[0-9 ]{1,3}\.[0-9 ]{1,3}$')
isipdom = re.compile('(.*)\.([0-9 ]{1,3}\.[0-9 ]{1,3}\.[0-9 ]{1,3}\.[0-9 ]{1,3}$)')



def whitelistfilter(x): return x not in WHITELIST
  # filters array on WHITELIST

def perlfieldatom(field):  #ONLY works on single instances; use this if you want a int returned, not a List
  t = field.replace('n','')
  if t == field:
    return(int(t) - 1)
  else:
    return(int(t) * -1)

def perlfield(field):
  # Input can be singleton or array or implied list of fields with 'x' as delimiter: 5x1nx3 -> [4,-1,2]
  # Each element is Field Number which is converted to 0 index, or negative index if 'n' is appended
  # additional alternate title appended with :AltTitle.

  alttitle = False  # possible redundant; handles alttitles too
  if field == '':
    return field

  a=[]  
  if not isinstance(field,list):  
    field,alttitle =  re.match('([^:]*):*(.*)',field).groups()
    if re.search('x',field):
      field = re.split('x',field)
    else:
      field = [field]

  for e in field:
    a.append(perlfieldatom(e))

  if alttitle:  # special case, return tuple, but be sure handle correctly in calling function
    return((a,alttitle))
  else:      
    return a

def find_delim(line,delimiter):
  # *** searches for delimiter in this order: UserSpecified, '\t', ',', ' '
  # *** This is not intended as a robust delimiter parsing script, as 99% of my workflow is <TAB> delim
  if delimiter:  # User explicitly stated delimeter
    if re.search(delimiter,line):
      return delimiter
    else:
      sys.stderr.write(_Y + 'ROOT_GETOPT.py, failed to find requested delimiter: ' + _W + delimiter + '\n' + _E)
      sys.exit()
  if re.search('\t',line):  #default is tab
    return '\t'
  elif re.search(',',line):  # NAIVE use of ',' for now
    if re.search('"',line):
      sys.stderr.write(_Y + 'ROOT_GETOPT.py, autoconverted to delimiter: found commas and ", this only support naive CSV: use -C file to convert csv file as input' + _E + '\n')
      sys.exit()
    return  ','
  elif re.search(' ',line):
    return ' '
  else:
    return False
    # sys.stderr.write(_Y + 'ROOT_GETOPT.py, autoconverted to delimiter failed, only tabs and commas currently sypported \n' + _E)

# *** for sgrep script

def find_file(datafile):
  # **** Find datafile in current DIR, with .map ext, or in DATADIR
  # **** Return opened file pointer
  if os.path.exists(datafile):  
    return  open(datafile,'r')  #  option to have 'trigger' IP as second field, may be multiple IPs, csv
  elif os.path.exists(datafile + '.map'):
    return  open(datafile + '.map','r')  #  opti
  elif os.path.exists(DATADIR + datafile):    
    return open(DATADIR + datafile +  'r')
  elif os.path.exists(DATADIR + datafile + '.map'):
    return open(DATADIR + datafile + '.map', 'r')  #  option to have 'trigger' IP as second field, may be multiple IPs,
  else:
    sys.stderr.write(_Y + 'ROOT_GETOPT.py, file does not exist: ' + _W + datafile + _E + '\n' )
    sys.exit()

def getopt_qual(args): 

  # **** parse list of field and comparator pairs into List of truples:
  # **** ( field #,  Value,  Comparator)  
  # **** Value is either text, numeric (negative numbers use ###.##n  syntax), file of values, or A different field: F5 means compare to 5th field 
  # **** Comparator is:  numeric: gt,lt,== (1.0 == 1.00).  text/regex: !=,~=,~.   Append 'f' to denote that value is a file.
  # **** Default is 'AND' logic; If 'OR' logic is desired, *first* argument in args is 'OR'.
  # **** Single parenthetical switch in logic
  # **** Returned data structure:    
  # **** First element of list is a list with Logic ('AND' | 'OR' ) and # of compare truples 
  # **** Example:  OR 3 100gt 3n 30lt 6 english_currency=f  ( english_currency == "USD\nCAN\nGBP' ) ==>
  # ****  [['OR', 3], ([2], '100', 'gt'), ([-3], '30', 'lt'), ([5], {'USD': 1, 'CAN': 1, 'GBP': 1}, '==')]
  done=[]
  logic =[]
  if args[0] == 'OR' or args[0] == 'AND':
    logic.append(args[0])
    del args[0]
  else:
    logic.append('AND')   # keep placeholder  for logic

  if len(args) % 2 != 0:
    sys.stderr.write(_Y + 'ROOT_GETOPT.py: incorrect number of qualifier pairs: ' + str(args[-1]) + '\n' + _E)
    sys.exit()
  for i,q in enumerate(args):
     a = []
     if i % 2 != 0:   # unflatten list into list of duples, convert to truples; continue because already processed this entry
       continue

     a.append(perlfield(q))  # Field #
     q = args[i+1]  # qual pair to field value

     # special case, value is different *field*, not constant.  
     m = re.match('F([0-9]+n*)+(.*)',q)
     if m:
       t = 'F' + str(perlfieldatom(m.group(1)))
       a.append(t) 
       a.append(m.group(2))
       #done.append(tuple(a))  # convert list to tuple

     else:
       # ********* First are numercial matches, must end in gt or lt, with optional P for parenthetical logic switch  ********
       # **** Additional value processing:  'k' = thousands, 'n' = negative. 
       # **** Add as needed dhm time deltas
       m = re.match('([0-9.]+[kn]*)+([lg]tP*)$',q)
       if m:
         if re.search('n$',m.group(1)):  # 'n' at end means value was negative
           a.append('-' + m.group(1)[:-1])
         elif re.match('k$',m.group(1)):  # 'k' at end means value is in thousands. No, cannot combine 'k' and 'n' syntax. 
           a.append(str(int(1000 * float(m.group(1)[:-1]))))
         # **** Option to add additional processing, namely handle hour/day/minute comparisons:
         # **** i.e.  4dlt  => timestamps less than 4 days old
         else:
           a.append(m.group(1)) 
         a.append(m.group(2) )   #

       else:
         # ********  Next are text matches...  **********
         # **** No comparator (default) is equality; '!=' is not equal
         # **** Regex: =~ , !~ .  '~~' is special case compare
         # **** Because compare characters '=~!' confound arg parsing: Only allow '=' in value, or singleton '~' '!' value 
         # trailing '[fF]'  means compare values are in a file:   datafile=f  will read datafile into dictionary for doing compare
         # F = case sensitive regex match from file.  [fF]#  denotes alternate field # to extract values from file
         if re.search('=.*=',q):  # '=' in both value and comparator.  Do not allow '~ or !' for regex compares   
           q = q.replace('=','@@',1)

         # ********* Parenthetical matching, appending PP to value, switches polarity from AND to OR, single time  ********
         parens = False
         if re.search('PP$',q):  # Use 'PP' to denote parenthetical logic for text fields since can have 'P' at end of value
           q = q[:-2]
           parens = True

         m = re.match('([^!~=]*)([!~=][!~=]*)(.*)$',q)
         if m and m.group(3) and m.group(3)[0].lower() != 'f': # text to match had a single '[!~=]', is just a straight equality match.
           m = None
         if m is None:    # straight equality match; 
           if q == 'UU':  # ** unicode;  short cut for filtering for any unicode.  maybe.
             a.append('[\\x80-\\xFF]')
           else:
             a.append(q)    
           a.append('')   # default compare operator
         elif len(m.group(2)) == 3:  # special case regex compare on single character: '~' | '!' 
           a.append(m.group(2)[0])
           a.append(m.group(2)[1:])
         else:
           compvalue = m.group(1)
           comparator = m.group(2)
           filecompare = m.group(3)
           if compvalue == 'UU':
             compvalue = '[\\x80-\\xFF]'
           if re.search("@@",compvalue):  # return protected '='
             compvalue = compvalue.replace('@@','=',1)              
           if not filecompare:  # *not* a file compare
              a.append(compvalue)
              a.append(comparator)
           else:  # *******************  File of values *************************
             # *** Determine which field value is in: Default is first
             if re.search('[0-9]',filecompare):
               valfield = perlfieldatom(filecompare[1:])
             else:
               valfield = 0
             # *** find and open data file
             inputfile = find_file(compvalue)
             d={}

             inline = inputfile.readline()
             delim = find_delim(inline,"") 

             while inline:
               inline = inline.rstrip()
               if not re.match('#',inline) and inline:  # ignore of blank and commented lines
                 if delim:  
                   fline = inline.split(delim)
                   # **** Add capability of aggregating multiple fields into one, if ever needed again
                   compvalue = fline[valfield]
                 else:
                   compvalue = inline
                 if re.search('~',comparator) and not re.match('~~',comparator): 
                   compvalue = re.sub('\)','\)',compvalue)  # escape parenthese
                   compvalue = re.sub('\(','\(',compvalue)
                   compvalue = compvalue.rstrip()          # ****** open question if we want to strip white space always *****
                   if filecompare[0] == 'F':  # Case sensitive match; 
                     regc = re.compile(compvalue)
                   else:
                     regc = re.compile(compvalue,re.I)
                   d[regc] = filecompare  # 'key' is regex, we loop through this (no need to be dict), usually this data structure *is* lookup dict; value will be the regex in text form

                 else:
                   compvalue = compvalue.rstrip()          # ****** open question if we want to strip white space always *****
                   if compvalue in WHITELIST:  # if user is explicitly looking for matches in whitelist, do NOT filter out whitelist
                     d['WHITELIST'] = 1
                   d[compvalue] = 1

               inline = inputfile.readline()
             # ******** Done reading in file **********

             a.append(d)  
             a.append(comparator)
             if parens:  #*** glue back on parenthetical logic marker
               a[-1] += 'P'

     done.append(tuple(a))  # convert list to tuple

  logic.append(len(done))  # first element is logical_or type, and total number of constraints
  done.insert(0,logic)
   #sys.stderr.write(_Y + str(done) + '\n' + _E)
  return done

def ipqualifier(ip,db):
# **** special use case for semi flexible quasi-cidr IP lookup: by IP2, IP3 IP4 ***
# **** RETURN IP match, NOT db match, as use the IP in many2one ***
  popip=re.compile('\.[^.]*$')
  nip = re.sub(' ','',ip)   # lookup non pretty print

  if nip == '...':
    return (nip,4)
  if nip in db:
    return (nip,4)
  else:
    nip = popip.sub('',nip)
    if nip in db:
      return (nip,3)
    else:
      nip =popip.sub('',nip)
      if nip in db:
        return (nip,2)
      else:
        return ('..',False)
      
    

def qualifier(qual,data,quickcheck=True):
# Generic filter module: takes 'qual' qualifier, data array, and various modifiers, returns match T/F, and bitarray of which elements in qual matched
# qual = list of truples (field, value, conditional)
# quickcheck:
#      default is to bail once FALSE is found for AND, and TRUE is found for OR
#      quickcheck=False  will check all qualifying truples, and return bitarray of which matched
#      Note need to convert timestamps to epoch time for compares. This probably warrants refactoring
# Returns array with all that match, as well as bitfield with which fields matched

  timeconvert = False
  if isinstance(quickcheck,tuple): # Unpack duple of booleans
    for e in quickcheck:
      if e == 'Time':
        timeconvert = True
      elif e == 'CheckAll':
        quickcheck = False

  ts=(re.compile(' *$'))  # trailing spaces.  we could also strip trailing spaces
  noescape=re.compile('\\033\[[39]*[0-9]m')
  parens = False   # parenthetical logic, convert pair of qualifiers to opposite logic
  logical_or = False  # logical_or is defaul AND, ==0, set to OR ==1, if first argument is 'OR'
  bitfield = 0  # this allows for record of *which* of many quals were matched,,,
  matched = [] # stores *values* that did match

  if not qual:  # no qualifier actually passed, assume all match
    return (1,[1])
  for i,q in enumerate(qual):
    if (i==0):  # first element is ALWAYS logical_or element, and size
      if q[0] == 'OR':
        logical_or = True
      continue

    bit = 2**(i-1)  # presence of OR skews bitfield, 
    match = False

    # **** Optional to combine multiple fields to create value for comparison ****
    val = False
    if isinstance(q[0],tuple): # multiple fields, with alternate default delim
      delim = q[0][1]
      val = q[0][0]
    elif len(q[0]) > 1:  # multiple field keys, but with default '_' delim
      delim = '_'
      val = q[0]

    if val:
      tval = []
      for eval in val:
        dq = re.sub(' *$','',data[eval])  # remove space padding if it exists
        if dq != '..':  # dont use voids in key
          tval.append(dq)
      if len(tval) > 1:  # wasnt' really multiple fields, since there were voids
        val = delim.join(tval)
      else:
        val = tval[0]
    else:
      if q[0][0] > len(data):
        sys.stderr.write(_Y + "ROOT_GETOPT:qualifier Requested field does not exist in input stream:" + str(q[0]) + "\n" + _E)
        return ("FAIL","FAIL")
      val = data[q[0][0]]

    # ***** Trailing spaces: if the qualifier does not have trailing space, remove from val.  If qualifier value is dict, trailing spaces were already removed
    if isinstance(q[1],dict) or not re.search(' $',q[1]):  
      val = ts.sub('',val)  # removes trailing spaces 

    # *** Remove any escape codes (shell color codes typically)
    val = noescape.sub('',val)  

    if val == 'NA' or val == '':  # **** my preference to store 'NA' and Voids as '..'
      val = '..'
    cval = q[1]
    
    # *** Compare two fields to each other: denoted with F. ***
    if isinstance(cval,str) and re.search('^F([0-9-]+)$',cval):  # *** If we add 'hdwm' compare: add ([hdwm]?) 
      cval = data[int(cval[1:])]
    comp = q[2]

    if timeconvert and not re.search('~',comp):  # do not convert timestamps if doing regex!; also need way to turn of timecovert if never used for speed reasons?
      val,day= timeconvert(val)

    if comp != '' and comp[-1] == 'P':
      comp = comp[:-1]
      parens = True

    # ********* Determine if this value comparison is T/F ***************
    if (comp == ''):  # straight exact match ( default strip trailing spaces )
      if val == cval:  
        match = True         
    elif comp == '!=':
      if val != cval:
        match = True

    # ********* numerical compare; == is for equality with floats and rounding error
    elif (( comp == 'gt' or comp == 'lt' or comp == '==') and val != '..'):  # **** ignore 'void' values for numeric compare 
      val = val.replace(",","")
      val = val.replace("%","") #  remove '%' from '%98.9' values,
      if val == '..':  # **** Connsider void fields as value of '0'; MUST change elif statement -3 lines.
        val = 0  

      # **** Default is to fail if *any* value in numeric compare cannot be converted to float ****
      try:
        val = float(val)
      except ValueError:
        sys.stderr.write(_Y + 'PARSE compare error, string where numeric expected: ' + val + '\n' +  _E)
        match = False
        return bitfield,[]
        # sys.exit() # add optional default fail if is string...
      try: 
        cval = float(cval)
      except ValueError:
        sys.stderr.write(_Y + 'PARSE compare error, string where numeric expected: ' + cval + '\n' +  _E)
        match = False
        return bitfield,[]

      if comp == 'gt':  # *** Note, gt is actually gte.
        if val >= cval:
          match = True
      elif comp == 'lt':
        if val < cval:
          match = True
      elif comp == '==':  # equality for floats!
        if val == cval:
          match = True
        elif cval > 1:
          if abs(cval - val)/(cval + val) < .005:  # allowed 1% error if ints
            match = True
        else:  
          if len(str(cval)) > len(str(val)):  # see if smallest sig figures is in bigger:  1.234 = 1.2345
            t = val    # swap so val is > cval
            val = cval
            cval = t
          aval = (val + cval)/2
          comp = abs(val-cval)/aval
          while aval < 1:
            aval = aval *10 
          if comp * aval < .5:
            match = True

    # *********** Dictionary of values from file ****************
    elif isinstance(cval,dict):  
      
      if not re.search('~',comp):  # straightforward hash/dictionary compare
        if val in cval:
          match = True
        if comp == '!=':
          match = not match

      else:

        # **** Bespoke code for looking for keyword stuffing in spam URLs...
        if comp == '~~':
          if 'FULLURL' not in cval:  # default is is to look only at path/file portion, NOT domain
            mm = isurl.match(val) # .groups()
            if mm:
              val = mm.groups()[1]

          s = re.sub('%20',' ',val.lower())
          s = re.sub('[,._\-/=&\?+]',' ',s).split() # neat, split on commas
          # **** Warning, we are prefiltering whitelist terms.  so cannot match if that is what you wanted! ***
          if 'WHITELIST' in qual[1][1]:
            fs = s  # i.e., do not filter out whitelist
          else:
            fs = filter(whitelistfilter,s)

          match = 0
          for efs in fs:
            if efs in cval:  # here we can do paired matching!
              if 'PAIRWISE' in cval:
                match += 1
              else:
              #  print _Y,"yeah",efs,_E
                match = efs
                break
          if 'PAIRWISE' in cval and cval['PAIRWISE'] > match:
            match = False

        # ******* List of regex matterns to match:  ing$, ed$ 
        else:
          # **** Orphan code to allow threshold of # of matches from list of regexes
          if len(q)> 3:
            pairs = int(q[3])
          else:
            pairs = None
          n = 0

          match = []
          for e in cval:
            if e.search(val):
              match.append(cval[e])
            if match and quickcheck:  # this allows to count up minimum match to count as a match, or do exhuastive search
              if pairs:
                n += 1
                if n == pairs:
                  break
                else:
                  match = False
              else:
                break
          if re.search('!',comp):
            if match:
              match = False
            else:
              match = True
    
    # **** Balance of text compares ****
    elif comp == '!=':
      if val != cval:
        match = True
    elif comp == '~=' or comp == '=~':   # either syntax supported
      if re.search(cval,val):
          match = True
    elif comp == '!~':   # regex not match
      if not re.search(cval,val):
        match = True
    else:  # This should never get here
      if val == cval:  
        match = True             # so, this would mean, 1  1.0  would not equate.

    if match:
      if comp == '~~' or isinstance(match,list):
        bitfield = match
      else:
        bitfield += bit
      matched.append(val) # may not work for all comparisons

    if quickcheck and ((match  and logical_or) or (not match and not logical_or)):  # if OR and any match, if AND and an mismatch, finish, (default is quick check)
      if not match: # failed match!
        matched = []
      return bitfield,matched

    if parens:  # can now ONLY go from AND logic switch to OR.  Due to quickcheck
      logical_or = not logical_or
      parens = False  # this remembers that this was a logic switch


  if not match and (logical_or == quickcheck):
      matched = []

  return bitfield,matched


# *** color printing shortcuts for escapes

_BM = '\033[95m'
_BB = '\033[94m'
_BG = '\033[92m'
_BY = '\033[93m'
_BR = '\033[91m'
_BD = '\033[90m'
_BC = '\033[96m'
_BW  = '\033[97m'
_D = '\033[30m'
_R = '\033[31m'
_G = '\033[32m'
_Y = '\033[33m'
_B = '\033[34m'
_M = '\033[35m'
_C = '\033[36m'
_W = '\033[37m'
_YY = '\033[43m'
_E = '\033[39m'

