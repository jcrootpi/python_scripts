#!/usr/bin/python2.6 -tt

# S(uper)Grep, expanded field specific 'grep' functionality 
# JRoot 11-2013

import sys
import os
import argparse
import random
import rootparse
import root_getopt
import re
import csv
from operator  import xor
from argparse import RawTextHelpFormatter
import time

# **** Ascii escape color codes ***
_D = '\033[30m'
_R = '\033[31m'
_G = '\033[32m'
_Y = '\033[33m'
_YY = '\033[1m\033[33m'
_BB = '\033[34m'
_B = '\033[1m\033[34m'
_M = '\033[35m'
_C = '\033[36m'
_W = '\033[37m'
_YY = '\033[43m'
_RR = '\033[1m\033[31m'
_E = '\033[0m'  
_BD = '\033[90m'


parser = argparse.ArgumentParser(description='SGREP: super grep: narrow grep to specific fields.  Field# Comparator Field#2 C#2...  Multiple conditionals are AND, Prepend "OR" otherwise. \n  Comparator => ValueCompare moooshed together, eg. 5gt. \n  Allowed Compares == gt (>=) lt (<), =~ regex, !~ reverse regex.  Default is ==, i.e, exact match.  "UU" is shortcut for unicode regex: UU=~ or UU!~.  Not fully pinned down preceeding/trailing whitepsace.\n  Value can be list of elements in file:  Filename=f.   Value from file can be Alternate Field: =f#',formatter_class=RawTextHelpFormatter)   # <== list whatever is not flagged, analagous to\


parser.add_argument('fields', metavar='N', nargs='*',
                   help='sgrep  Field# valueCmp ...  First field can be optional file, though cannot start with number *and* have no period')
parser.add_argument('-t', action="store", dest="threshold", type=int,default=1,
                          help='threshold of what sgrep matches in ggrep mode, ')
parser.add_argument('-g', dest="group",nargs='?',
                          help='Group, field(s) to group by. If *any* line matches conditionals, print out all lines. C groups by class C')
parser.add_argument('-v', action="store_true", dest="reverse",default=False,
                         help='reverse; for non group grep, simply reverses logic.  For group grep, applies to whole group.')
parser.add_argument('-F', action="store", dest="filename",
                         help='Filename: save matched lines to file. Default is to stream reverse, use -p to suspress unmatched data.  Overwrites existing file.')
parser.add_argument('-d', action="store", dest="delimiter", type=str,nargs='?',default = 'Default',
                          help='delimiter: will auto find delim in order: "\t" "," " ".  No argument will convert found delim to <TAB>. Any other arg forces that delimiter. If two characters, will conver to secodn char, if 3, concert to tab.')
parser.add_argument('-b', action="store", dest="boolean", default=False,nargs='?',
                          help='Boolean: Adds field instead of filtering. Default is "YES", or text as provided. "B" will print bitwise record of match. Append :AltTitle to argument')
parser.add_argument('-B', action="store", dest="booleanII", default=False,nargs='?',
                          help='Boolean: same as -b, but inserts result after first field argument')
parser.add_argument('-O', action="store", dest="overide", default=False,nargs='?',
                          help='Overide field mismatch; if calling out field that does nto exist, punt line. Any arg: remove all lines that do not match')
parser.add_argument('-H', action="store", dest="header", default=0,type=int,nargs='?',   
                          help='Header: no flag, exists and preserve; -H remove header, -H 1 header does not exist')
parser.add_argument('-c', action="store", dest="color",type=int,default=False,nargs='?',help='Colors/highlights match: will NOT filter. default is whole line 1 == field(s)')
parser.add_argument('-p', action="store_true", dest="printv",default=False,help='suppresses printing of non matched data with -F opion.')
parser.add_argument('-C', action="store", dest="csvfile", help='CVS file as input; cannot stream csv for some strange reason')
parser.add_argument('-D', action="store_true",dest="debug",default=False,help='Debug flag')

pwd = os.getcwd()
homedir = os.path.expanduser('~')
DATADIR = homedir + '/data/'



# ******************************  MAIN **************************************

# ******* Finish processing input flags *******

args = parser.parse_args()

if re.match('[^0-9]',args.fields[0]) and args.fields[0] != "OR" and args.fields[0] != "AND":  # If 1st argument is NOT a number (index#) or "OR", must be optional input filename
  filename = args.fields.pop(0)
else:
  filename = ''

# **** This creates a qualifier data structure; see below for more details
qualifier = root_getopt.getopt_qual(args.fields)

if args.debug:
  print _M,qualifier,_E

delimiter = False
if args.delimiter == 'Default' or args.delimiter is None:
  pdelimiter = '\t'  # this is a 'printing' delimiter, incase different from input stream delimiter 
elif args.delimiter:
  delimiter = args.delimiter[0]
  if len(args.delimiter) == 2:
    pdelimiter = args.delimiter[1]
  elif len(args.delimiter) > 2:
    pdelimiter = '\t'
  
if not args.color:
  if args.color is None:
    args.color = 3  # default, line filtering

if args.overide is not False:
  if args.overide is None:
    args.overide = -1
  else:
    args.overide = "C"  # ANY argument for this flag will be to 'Clean'/delete any lines w/o # of fields as header line

# *** check overide argument for maximum field requested
if  args.overide != "C":  # cleanup override doesnt' care, just deletes any line that is not right size
  for e in qualifier[1:]:
    if args.overide and e[0]> args.overide: # find max requested field
      args.overide = e[0]

reverse = args.reverse   # two flavors, group reverse, and single line reverse

gfield=[]
classcgroup = False
if args.group:
  greverse = False
  if args.reverse:
    greverse = True
    reverse = False
  if re.search('C',args.group):
    classcgroup = True
    gfield = root_getopt.perlfield(args.group[:-1])
  else:
    gfield = root_getopt.perlfield(args.group)

if args.header is None:   # no flag == 0, header exists, and print,  -H 1 ==> -1, means no header exists, -H   ==> 1, delete header
    args.header = 1
else:
    args.header *= -1

if args.threshold is None:  # combined with grouping, threshold match count
    threshold = 0
else:
    threshold = int(args.threshold)

if args.csvfile:
  csvfile = open(args.csvfile,'r')
  infile = csv.reader(csvfile, delimiter=',', quotechar="'")
elif filename == '': 
  infile = sys.stdin
else:
  infile = open(filename,'rU')

if args.filename:
  outfile = open(args.filename,'w')

ep = sys.stderr.write  # cause Google dinged you if code width was over 84 chars.

#  ********* Process Header.  Add additional fields as needed *******
size = 0
header = False
if args.header >= 0:
  if args.csvfile:
    try:
      flist = infile.next()
    except:
      sys.stderr.write(_Y + "SGREP.py, input csv file is MT! \n" + _E)
      sys.exit()
  else:        
    inline = infile.next()  # readline()
    delimiter = root_getopt.find_delim(inline,delimiter)
    if delimiter:
      inline = re.sub(delimiter + ' *$',delimiter + '..',inline)
    line = inline.strip()
    if len(line) == 0:
      sys.stderr.write(_Y + "SGREP.py:  Yo, someone stole your data stream!\n" + _E)
      sys.exit()
    header = line
    flist = line.split(delimiter)
  headerlist = list(flist)

  size = len(flist)      # records # fields of first line
  if args.header == 0:  # default is header exists
    a = []
    if args.booleanII is None: # using -B instead of -b, *inserts* the result
      args.boolean = 'YES'
      args.booleanII = True
    elif  args.booleanII:
      args.boolean = args.booleanII
      args.booleanII = True

    if args.boolean is None:
      args.boolean = 'YES'
    if args.boolean:  # this is only time we *add* fields!
      args.boolean = args.boolean.split(':')
      if len(args.boolean) == 2:
        t = args.boolean[1]
      else:
        t = 'Boolean'
      if args.booleanII:  # insert boolean, after first arugment
        flist[qualifier[1][0][0]] += pdelimiter + t
      else:
        flist.append(t)
      args.boolean = (args.boolean[0],args.booleanII)
    if args.filename:
      outfile.write(pdelimiter.join(flist) + '\n')
      if args.printv:
        print pdelimiter.join(flist)
    else:
      print pdelimiter.join(flist)

# *************  Process input data/stream *****************

grouping = False
pgrouping = False
gdata = []
match = False
delimconvert = False  
linenumber = False
reading = True

while reading:
  try:
    inline = infile.next() 
  except:  # end of input; check group grep criteria
    reading = False
    if gfield:
      grouping = "DONE"
    else:
      break

  if args.csvfile:  # csv is already converted to array!
    flist = inline
    line = pdelimiter.join(flist)  
  else:
    if not linenumber:  # just in case no header, still need to find delimiter!
      if args.header < 0:  # have not processed a line yet!
        delimiter = _find_delim(inline,delimiter)
      linenumber = 0
      if delimiter:  # Address various void data scenarios
        istrailingvoid = re.compile(delimiter + ' *$')
        isstartingvoid = re.compile('^' + delimiter)
        isvoid = re.compile(delimiter + delimiter)
      if delimiter != pdelimiter:
        delimconvert = True

    linenumber += 1
    inline = re.sub(r'\r','',inline)   # Remove errant ^M
    if delimiter:      # Following could be skipped if we know we have cleaninput!. 
      inline = istrailingvoid.sub(delimiter + '..',inline)   # trailing voids (otherwise strip will remove)
      inline = isvoid.sub(delimiter + '..' + delimiter,inline)   # replace voids with '..' placeholder
      inline = isvoid.sub(delimiter + '..' + delimiter,inline)  # twice for repeated voids
      inline = isstartingvoid.sub('..' + delimiter,inline) # initial void
    line = inline.rstrip()
    if header and header == line:  # remove dupe headers
      continue
    flist = line.split(delimiter)

  # ****** grouped grepping on lines grouped by alternate field(s) ***********
  if gfield:
    grouping = ''
    for e in gfield:
      if classcgroup:  # special case ClassC IP group
        grouping += re.sub('\.[^.]*$','',flist[e])
      else:
        grouping += flist[e]

  if pgrouping:
    if grouping != pgrouping:  # ******  Found grouping boundary
      if match and (not args.threshold or match >= args.threshold): # optional threshold filter
        match = True
      if greverse:      # group grep reverse
        match = not match
      if args.filename: # -f option: save matched lines to file
        match = not match

      if match:
        if not args.threshold or match >= args.threshold:
          if delimconvert:
            sys.stderr.write(_Y + "SGREP.py:  delimiter converting and grouping not yet coded\n" + _E)
            sys.exit()
          for e in gdata:
            print e
      elif args.filename:
        for e in gdata:
          outfile.write(e + '\n')

      gdata = []
      match = False
    pgrouping = grouping

  # ****** Check to see if # of fields align ******
  if not size:
    size = len(flist)
  if (size != len(flist) and reading):  
    if args.overide is not False:      # *** if override, continue sgrep regardless unles...
        if args.overide == 'C':   # **** 'Clean opyion; simply remove any corrupt lines. Confirm is safe to do
          continue
        elif args.overide >= len(flist) and linenumber < 2:   # if overriding, we expect corrupt lines; only if the first line is missing fields do we raise exception
            ep(_Y + 'SGREP: size problems at line ' + _M + str(linenumber) + _C + ' Requested a field that does not exist. Aborting\n' + _E)
            exit()
    else:
      try:
        t = infile.next()
      except:
        ep(_Y +'SGREP: Sloppy end of file: ' + _W + line + ' \n' + _E )
        exit()
      ep(_Y + 'SGREP: size problems at line ' + _M + str(linenumber) + _C + pdelimiter +  str(size) + '!=' + str(len(flist)) + '\n' + _W + line + _E +  '\n')
      # ****** Default action is to continue processing; adjust as needed ******

  if gfield:
    gdata.append(line)  # save input stream for printing conditional on group grep criteria
    pgrouping = grouping


  # *** qualifier takes a qualifier data structure, compares it to the line of data in array form.  Last value is 'quick' check, (TRUE) or exhaustve check (FALSE)
  # *** Returns boolean 'c', and bitfield of which of qualifiers matched; use FALSE to use bitfield
  # *** Structure: [ ['AND/OR', '#-of-qualifiers'], Qualifier1, Qualifier2 ...]
  # *** Each Qualifier is truple:  ( [Index], 'Value', 'Comparator' )
  #        Value can be string, numeric or dict of strings
  #        Comparators are:   '' = exact match
  #                           !=  = not equal
  #                         gt/lt = numeric compares; gt is currently >=
  #                         =~/!~ = regex compare

  if (args.color == 1 and qualifier[0][0]== 'OR') or args.booleanII:  # If we want to highlight OR fields, must do this... 
    bitfield,c =  rootparse.qualifier(qualifier,flist,False)
  else:
    bitfield,c =  root_getopt.qualifier(qualifier,flist,True)

  # if ((False if reverse else c) if c else reverse):  # Syntax in case 'xor' is not supported of available
  if xor( bool(c), reverse):   
    if gfield:
      if not match: # count number of matchs for threshold match filtering 
        match = 1
      else:
        match += 1
    else:
      if args.filename:
        outfile.write(line + '\n')
      else:
        # ***** color highlight lines that match, *NOT* filter/grep from input stream
        if args.color: 
          if args.color > 1:     # default is whole line is highlighted
            sys.stdout.write(_Y + line + _E + '\n')
          else:                  # Alternatively, highlight individual Field(s) that matched search criteria
            for ii,q in enumerate(qualifier[1:]):
              pos = 2 ** ii
              if pos & bitfield:
                flist[q[0][0]] = _Y + flist[q[0][0]] + _E
              if isinstance(q[1],str) and re.match('F',q[1]):  # was error when cval was dictionary!
                flist[int(q[1][1:])] = _Y + flist[int(q[1][1:])] + _E
            print pdelimiter.join(flist)

        # **** Adding field with grep status, *NOT* filtering
        elif args.boolean: 
          if args.boolean[1]:  # this is an insert!
            flist[qualifier[1][0][0]] += pdelimiter + args.boolean[0]
          else:
            if args.boolean[0] == 'B':
              flist.append(bitfield)
            else:
              flist.append(args.boolean[0])
          print pdelimiter.join(flist)
        elif delimconvert:  # **** If input file was not /t delimited, will print out in tabs.
          print pdelimiter.join(flist)
        else:          
          print line
  elif (args.filename and args.printv) or args.color >= 1:   # TBD, have not finished -b option...
    print line
  elif args.boolean:  # this is not filtering, so print out anyways!
    if args.boolean[1]:  # this is an insert!
      flist[qualifier[1][0][0]] += '\t..'
    else:
      flist.append('..')
    print pdelimiter.join(flist)

