# This program uses an external source to check how many times a passowrd has been hacked
# user can enter their password input on the command line

# make imports
import requests
import hashlib
import sys

# this function make requests to the Api at pwned passwords which has a collect of stolen passwords
# the api uses hashing in its request (using the SHA1 algorithm)
# If password123 is the password that we are testing, hashed to CBFDA.....
# the first 5 character of its hash are used for k anonymity
def requestApiData(chars):
    url = 'https://api.pwnedpasswords.com/range/' + chars
    res = requests.get(url)
    
    #If error
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check your program.')
    
    return res


# gets the response, which is a list of hashed passwords and the number of times that its been breached
# compare the hashed pasword that we want to check with the ones in the list
def analyzeResponseCount(responseList, target):
    # Response is separated in ':' so we split ':'
    responseList = (line.split(':') for line in responseList.text.splitlines())

    # Compare with target in loop
    for password, count in responseList:
        if password == target:
            return count

    return 0 # not found

# hash password using hashlib sha1
def stolenApiCheck(password):
    # hash with sha1 hexadecimal uppercase
    convertSha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # take first 5 chars, save the rest in remainingChars
    fiveChars = convertSha1[:5]
    remainingChars = convertSha1[5:]

    response = requestApiData(fiveChars)
    
    return analyzeResponseCount(response, remainingChars)


#main
def main(args):
    #loop through args
    for password in args:
        #calls the checking function    
        count = stolenApiCheck(password)  

        if count: #if count exists then
            print(f'The password: {password} was hacked {count} times, be careful.')

        else:
            print(f'The password: {password} was NOT found, it has not been hacked.')

# user can gives many password inputs
main(sys.argv[1:])