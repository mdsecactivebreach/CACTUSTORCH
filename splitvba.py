import os;
import random;
import uuid; 
import string;
import sys;
import argparse;

def banner():
		with open('banner.txt', 'r') as f:
			data = f.read()

			print "\033[1;31m%s\033[0;0m" % data
			print "\033[1;34mSplits base64 encoded payload into chunks for VBA"
			print "\033[1;32mAuthor: Vincent Yiu (@vysec, @vysecurity)\033[0;0m"

def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

if __name__ == '__main__':
	banner()
	if ((len(sys.argv) > 3) or len(sys.argv) < 3):
		# must be not 1
		print "Usage: " + sys.argv[0] + " <input base64 encoded> <output file>"
		sys.exit(1)

	print "[*] Input file: " + sys.argv[1]

	f = open(sys.argv[1], 'r')
	code = f.read()
	f.close()

	# split into 100 char blocks
	output = split_len(code, 100)

	print "[*] Output file: " + sys.argv[2]
	f = open(sys.argv[2], 'w+')
	for a in output:
		f.write("code = code & \"" + a + "\"\r\n")
	f.close()
