####################################################################################
#                                                                                  #
# SECURITY 2014-2015                                                               #
# Name(s) : Cas van der Weegen [2566388]                                           #
# Study:    Computer Science                                                       #
# Course:   Security                                                               #
# Git: github.com/vdweegen                                                         #
#                                                                                  #
# Assignment: Challenge 4                                                          #
#                                                                                  #
# Usage:   python CrackChallenge4.py                                               #
#                                                                                  #
# Note: Unless instructed otherwise, this file shall be uploaded at the end        #
#       of the college year 2014/2015                                              #
#                                                                                  #
# Description:                                                                     #
#   I divided the passwords up in 3 blocks of 16 bytes, based on this cracking     #
#   of the passwords is done in 3 phases (tiers).                                  #
#                                                                                  #
#   Tier 1:  Tests all passwords as is, and tests all passwords with 1 character   #
# [moderate] added so that each password is 7 characters                           #
#                                                                                  #
#            After possibilities are found the are saved in tier1_passes           #
#                                                                                  #
#   Tier 2:  Tests all passwords, minus the first character. Up to two characters  #
# [slow]     are added so that all 6 and 7 character passwords that come AFTER     #
#            the first block are added.                                            #
#                                                                                  #
#            Optimalisation is done by checking if passwords start with the last   #
#            letter of the password in tier1_passes, if not they are skipped       #
#            since they wont be a match.                                           #
#                                                                                  #
#            After possibilities are found they are saved in tier2_passes          #
#                                                                                  #
#   Tier 3:  Final Tier, fastest. Last block is checked. All passwords, minus the  #
# [fast]     first two characters. Up to two characters can be added.              #
#                                                                                  #
#            Optimalisation is done by checking if passwords start with the last   #
#            two letters in tier2_passes, if not they are skipped. (this gives     #
#            an enormous speedup).                                                 #
#                                                                                  #
#            Time: Tier1 took approx. 2 hours                                      #
#                  Tier2 took approx. 6 hours                                      #
#                  Tier3 took approx. 20 minutes                                   #
#                                                                                  #
####################################################################################
import urllib,httplib2,os,itertools,string,sys

def main():
 # Define wordlist
 wordlist = "wordlist.txt"
 # Load Wordlist
 with open(wordlist, "r") as ins:
  passwords = []
  for line in ins:
   passwords.append(line.rstrip()) # Put in array, strip newlines
 ins.close() # Close File
 
 # All 16 byte blocks from the userlist
 pwlist = ['7ec41fed3c392510', '0b9b363227895743', '18409faefe1e5229',
           '7588f1e0ef4fa0ef', '7adbf79bffd7b6cb', '7283fec8b4d8cf75',
           'd9a9d325507bd98c', 'a904545000f969ea', '2f647874e90c1514',
           'e5d396511b98651d', 'ae67c52db947c354', 'e64d1a0e917fc005',
           '8497589179665ea8', '22454b55f40faef0', 'ea34f9815ef2f112',
           '724d72e292f765a6', '3dfcf48e313bef8a', '4b3965e93d78a9da',
           'bca3c905da866d1a', '9705faddcb4a8c8b', 'e5e5de2317446ff6',
           'd78243992d853f3a', '4f1e1d259d188619', '79a16fd86e28843a',
           '6eb43a7232593970', '06772c3736e440c2', 'aad3b435b51404ee']
 
 # Lists to hold found passwords
 tier1_passes = [] 
 tier2_passes = []
 tier3_passes = []

 # Holders for first (two) letter(s) 
 tier1 = []
 tier2 = []
 
 print "Starting Cracker..."
 beep()

 # Start Cracking
 with open("solved.txt", 'w') as outfile:
  for T in range(1,4):                                                     # Loop 3 time, once for each Tier
   print "Cracking Tier",T
   if T == 2:
    for x in tier1_passes:                                                 # Get last characters of tier1 passes
     tier1.append(x[-1:])
   elif T == 3:
    for x in tier2_passes:                                                 # Get last two characters of tier2 passes
     tier2.append(x[-2:])
   outfile.write("Begin Tier "+str(T)+'\n')
   for password in passwords:                                              # Loop through possible passwords
    if(T == 1):                                                            # Tier 1 Start
     password = password.lower()                                           # Lowercase (not really functional, easier)
     print password                                                        # In case of premature abort we know where we were
     content = check(password)[:16]                                        # Only first 16 bytes matter, check with hasher
     if content in pwlist:                                                 # See if it is one of the hashes we are looking for
      print content,"Matches with:",password                               # print of match
      tier1_passes.append(password)                                        # append if matched
      outfile.write(content+' Matches with: '+password+'\n')               # write to file
      beep()                                                               # beep, for unattended cracking
     
     for i in range(97, 123): 
      content = check(password+chr(i))[:16]
      if content in pwlist:
       print content,"Matches with:",password+chr(i)
       tier1_passes.append(password+chr(i))
       outfile.write(content+' Matches with: '+password+chr(i)+'\n')
       beep()
       
    elif(T == 2):                                                           # Tier 2 Start
     print password.lower()[0],">",password.lower()
     if password.lower()[0] in tier1:
      print "\tWorking...."
      password = password.lower()[1:]
      content = check(password)[:16]                                        # Only first 16 bytes matter, check with hasher
      if content in pwlist:                                                 # See if it is one of the hashes we are looking for
       print content,"Matches with:",password                               # print of match
       tier2_passes.append(password)                                        # append if matched
       outfile.write(content+' Matches with: '+password+'\n')               # write to file
       beep()                                                               # beep, for unattended cracking
      for i in range(97, 123):                                              # Add 1 Char at the end
       content = check(password+chr(i))[:16]
       if content in pwlist:
        print content,"Matches with:",password+chr(i)
        tier2_passes.append(password+chr(i))
        outfile.write(content+' Matches with: '+password+chr(i)+'\n')
        beep()
       for j in range(97, 123):                                             # Add Another Char at the end
        content = check(password+chr(i)+chr(j))[:16]
        if content in pwlist:
         print content,"Matches with:",password+chr(i)+chr(j)
         tier2_passes.append(password+chr(i)+chr(j))
         outfile.write(content+' Matches with: '+password+chr(i)+chr(j)+'\n')
         beep()
     else:
      print "\tSkipping...."
    elif(T == 3):                                                           # Tier 3 Start
     print password.lower()[0:2],">",password.lower()
     if password.lower()[0:2] in tier2:
      print "\tWorking...."
      password = password.lower()[2:]
      content = check(password)[:16]
      if content in pwlist:
       print content,"Matches with:",password
       tier3_passes.append(password)
       outfile.write(content+' Matches with: '+password+'\n')
       beep()
      for i in range(97, 123):                                              # Add 1 Char at the end
       content = check(password+chr(i))[:16]
       if content in pwlist:
        print content,"Matches with:",password+chr(i)
        tier3_passes.append(password+chr(i))
        outfile.write(content+' Matches with: '+password+chr(i)+'\n')
        beep()
       for j in range(97, 123):                                             # Add Another Char at the end
        content = check(password+chr(i)+chr(j))[:16]
        if content in pwlist:
         print content,"Matches with:",password+chr(i)+chr(j)
         tier3_passes.append(password+chr(i)+chr(j))
         outfile.write(content+' Matches with: '+password+chr(i)+chr(j)+'\n')
         beep()
     else:
      print "\tSkipping...."
 print tier1_passes
 print 
 print tier2_passes
 print
 print tier3_passes
 print
 print "Done!"
 outfile.close() 

# Connection Function
def check(password):
 # Disable SSL Verification :(
 http = httplib2.Http(".cache",disable_ssl_certificate_validation=True)
   
 # Construct Headers to Authenticate against security-home.work
 headers = {'Cookie' : 'rack.session=BAh7CkkiD3Nlc3Npb25faWQGOgZFVEkiRWNmNjI5MWVhNzg3M2U5MGM5OWZk%0AOTYyYWFmNTY1YWFjYzYxZmIwZTkwMTQzNDYwYWY1NDA3YzMwMzFlZjk3ODcG%0AOwBGSSIJY3NyZgY7AEZJIiUwMzY3NjhiZmVjZWZlYTU2YTMzYjZiYjQwYzFm%0AMjVkMgY7AEZJIg10cmFja2luZwY7AEZ7B0kiFEhUVFBfVVNFUl9BR0VOVAY7%0AAFRJIi0wNzQyMWE2MmJlMDBhMGQ0OWE0NjlkOTJhZGEyYWNiZjZkM2VjNmNk%0ABjsARkkiGUhUVFBfQUNDRVBUX0xBTkdVQUdFBjsAVEkiLWRkMTI1ODAzOTE1%0AZDRkZjdmYzc4ZmI5M2MxOTlhZWJlMGY2YTlkOWMGOwBGSSIMdXNlcl9pZAY7%0AAEZpXkkiC2NvbmZpZwY7AEZJIgIUAWV5SnViMjVqWlNJNkluVkhaV3BZTW5s%0ASE1XaHBjWFpHUkZoTmFVMTRNMGh4Wnpsb1JsZDNjWE5oSWl3aQpZMjl1Wm1s%0Abklqb2lRemRaVDAxcGNUZEJTMWRXUm1oTVEyOXdWa3h1U21WeWJXMHJXbkJW%0AYm1oUWFUTkIKUms5TU1EUXpSR0ZvTkhWRk5YTXJNRU5rYzNrd01XcEhYRzUz%0ASzJaT1pXa3JNa28wVm1oNWFsWnpNbmRGClRXTjFjemhJYTJONmJYcERhVmx3%0AWTBwdGN6ZEZNRkJ2TTNCNFVUVlljMUZGYm5aTlFYTTBNbTFjYm5CaQpUaXRE%0ATjIxblMwOXBOV3BOYkZRNWNYZFJWMFJhV0NKOQY7AFQ%3D%0A--0c7b6b713b764d1472d0fea4aab7e7c0ecaa807d',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Referer' : 'https://crypto4.security-home.work/',
            'Accept-Language' : 'en-US,en;q=0.8,nl;q=0.6',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36',
            'Connection': 'keep-alive',
            'Pragme': 'no-cache',
            'Content-type': 'application/x-www-form-urlencoded'}
 content = ""
 try:
  url = 'https://crypto4.security-home.work/hash/'+password
  response, content = http.request(url, 'GET', headers=headers)
 except UnicodeDecodeError:
  pass
 except httplib2.ServerNotFoundError:
  print "Could not find server, aborting... Last item was:",password
 except: # CatchAll, so we know when we've crashed and the program will continue to run
  beep()

 return content

# Beeper function to allow for unattended cracking
def beep():
 os.system('play --no-show-progress --null --channels 1 synth %s sine %f' % (2, 800))

# Main function
if __name__ == '__main__':
 main()