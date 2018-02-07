#!/usr/bin/python
import pydap, datetime, pytz, getpass, sys, argparse
from dateutil.parser import parse

def win32TimeConvert(wTime):
    try:
        epoch = datetime.datetime(1601, 1, 1)
        ms_since_epoch = int(wTime) / 10
        diffdatetime = epoch + datetime.timedelta(microseconds=ms_since_epoch)
        datestr = str(diffdatetime)[:-7] + ' +0000' 
        dt = parse(datestr)
        localtime = dt.astimezone (pytz.timezone('US/Pacific'))    
        return localtime
    except(ValueError):
        return "Error: Unable to obtain time. Unable to convert time_value=%s" % wTime

def processArgs():
    parser = argparse.ArgumentParser(description='accountdetails, LDAP User Account Details', prog='accountdetails')
    
    parser.add_argument('-u', '--user', metavar='<user>', help='The user account to query for')
    parser.add_argument('-g', '--group', metavar='<group>', help='The group to query for')
    parser.add_argument('-f', '--format', metavar="<format>", help='Format the output')
    parser.add_argument('-v', '--verbose', action="store_true", help='Print verbose output')
    return parser.parse_args()

def getCreds():

    options = processArgs()
    
    if options.user:
        user = options.user
    else:
        user = getpass.getuser()
        if not user:
            user = raw_input("Please enter your username for AD authentication: ")   
    
    print "Please enter the password for %s" % user     
    pw = getpass.getpass()
    return user, pw

def printLdapInfo(ldapInfo, output_format=''):
    if 'splunk' in output_format:
        timestamp = datetime.datetime.strftime(datetime.datetime.now(), "%Y-%m-%d %H:%M:%S")
        log_str = timestamp + " "
        log_str += 'Account_Expires="%s" ' % ldapInfo['accountExpires']
        log_str += 'Lockout_Time="%s" ' %  ldapInfo['lockoutTime']
        log_str += 'User_Account_Control="%s" ' %  ldapInfo['userAccountControl']
        log_str += 'Password_Last_Set="%s" ' % ldapInfo['pwdLastSet']
        log_str += 'Bad_Password_Time="%s" ' % win32TimeConvert(ldapInfo['badPasswordTime'])
        log_str += 'Bad_Password_Count="%s" ' % ldapInfo['badPwdCount']
        log_str += 'Last_Log_on_Time="%s" ' % win32TimeConvert(ldapInfo['lastLogon']) 
        log_str += 'Log_on_Count="%s" ' % ldapInfo['logonCount']
        log_str += 'When_Created_At="%s" ' % parse(ldapInfo['whenCreated'])
        log_str += 'When_Changed_At="%s" ' % parse(ldapInfo['whenChanged'])
        
        for member in ldapInfo['memberOf']:
            log_str += 'memberOf="%s" ' % (member)
        print(log_str)
                
    else:
        print("Account Expires value: %s" % ldapInfo['accountExpires'])
        print("Lockout Time value: %s" %  ldapInfo['lockoutTime'])
        print("User Account Control value: %s" %  ldapInfo['userAccountControl'])
        print("Password Last Set value: %s" % ldapInfo['pwdLastSet'])
        print("Bad Password Time value: %s" % win32TimeConvert(ldapInfo['badPasswordTime']))
        print("Bad Password Count value: %s" % ldapInfo['badPwdCount'])
        print("Last Log on Time value: %s" % win32TimeConvert(ldapInfo['lastLogon']))    
        print("Log on Count value: %s" % ldapInfo['logonCount'])
        print("When Created At value: %s" % parse(ldapInfo['whenCreated']))
        print("When Changed At value: %s" % parse(ldapInfo['whenChanged']))
    
        print "Member of value(s):"
        for member in ldapInfo['memberOf']:
            print member
        print('')

def ldapParseUserRecord(record, ldapInfo):
    neverExpires = '9223372036854775807'
    enabledAccount = '512'
    
    if (record['accountExpires'][0] == neverExpires or '0'):
        ldapInfo['accountExpires'] = 'Never Expires'              
    else:
        ldapInfo['accountExpires'] = win32TimeConvert(record['accountExpires'][0])
        
    if 'userAccountControl' in record:
        if enabledAccount == record['userAccountControl'][0]:
            ldapInfo['userAccountControl'] = "Enabled Account. The User-Account-Control attribute does not contain the UF_DONT_EXPIRE_PASSWD flag"

    if 'badPasswordTime' in record:
        if record['badPasswordTime'][0] > ldapInfo['badPasswordTime']:
            ldapInfo['badPasswordTime'] = record['badPasswordTime'][0]
    
    
    if 'badPwdCount' in record:
        ldapInfo['badPwdCount'] += int(record['badPwdCount'][0])

    if 'lastLogon' in record:
        if record['lastLogon'][0] > ldapInfo['lastLogon']:
            ldapInfo['lastLogon'] = record['lastLogon'][0]
                     
    if 'lockoutTime' in record:
        if record['lockoutTime'][0] == '0':
            ldapInfo['lockoutTime'] = '0'
        else:
            ldapInfo['lockoutTime'] = win32TimeConvert(record['lockoutTime'][0])
            
    if 'logonCount' in record:
        ldapInfo['logonCount'] += int(record['logonCount'][0])
    
    if 'pwdLastSet' in record:
        if '0' == record['pwdLastSet'][0]:
            ldapInfo['pwdLastSet'] = "Recent password reset, pending new password creation."
        else:
            ldapInfo['pwdLastSet'] = win32TimeConvert(record['pwdLastSet'][0]) 
    
    if 'whenChanged' in record:
        if record['whenChanged'][0][:-3] > ldapInfo['whenChanged']:
            ldapInfo['whenChanged'] = record['whenChanged'][0][:-3]
    
    if 'whenCreated' in record:   
        ldapInfo['whenCreated'] = record['whenCreated'][0][:-3]
    
    if 'memberOf' in record:
        ldapInfo['memberOf'] = record['memberOf']
    
    return ldapInfo

def ldapParseGroupRecord(record, verbose=False):
    for rec in record:
        rec = rec[0][1]
        try:
            print("Group Name: %s" % rec['name'][0])
            if 'member' in rec:
                for member in rec['member']:
                    member = (member.split(',')[0]).split('=')[1]
                    print("%s" % member)
                    if verbose:
                        ldapInfo = queryDomainControllers(queryUser=member)
                        return ldapInfo
            else:
                print("No members")
        except KeyError:
            print "Error"
        print('')

def queryDomainControllers(queryUser=None, queryGroup=None, verbose=False):

    
    ldapServers = ['test-dc-01.domain.com', 'test-dc-02.domain.com']
    
    
    ldapInfo = {'badPasswordTime':'', 'badPwdCount':0, 'lastLogon':'', 'logonCount':0, 'whenChanged':'', \
                 'accountExpires':'', 'lockoutTime':'', 'pwdLastSet':'', 'memberOf':'', 'whenCreated':'', 'userAccountControl': ''}
    
    for server in ldapServers:
        if verbose:        
            print('Query LDAP Server: %s' % server)
            
        if pydap.ldapConnect(server=server):            
            if queryUser:
                res = pydap.ldapSearch(searchFilter='sAMAccountName='+queryUser)
                if res:
                    record = res[0][0][1]
                    ldapInfo = ldapParseUserRecord(record, ldapInfo)
                else:
                    continue        
            
            if queryGroup:
                
                res = pydap.ldapSearch(searchFilter='(&(objectClass=group)(cn=%s))' % queryGroup)
                if res:
                    ldapInfo = ldapParseGroupRecord(res, verbose=verbose)
                    break
                else:
                    continue 
                
                
        else:
            print 'Failed Querying LDAP Server: %s' % server
    
    return ldapInfo  

def main():
           
    options = processArgs()
    
    queryUser = None
    queryGroup = None
    verbose = False
    out_format = ''
    
    if options.verbose:
        verbose = True
    if options.format:
        if 'splunk' in options.format:
            out_format = 'splunk'
        else:
            sys.exit('Unrecognized format. Exiting...')
    if options.user:
        queryUser = options.user
    if options.group:
        queryGroup = options.group
    if not options:
        sys.exit('No query specified. Exiting...')
    
 
    #user, pw = getCreds()
    
    attempts = 0
    successful = False
    while not successful:
        #print "Using the username: %s" % user
        #successful = pydap.ldapConnect(user, pw)
        successful = pydap.ldapConnect()
        
        if not successful:
            if attempts < 2:
                print('Error: Invalid Credentials. Try again.\n')
                
                #user, pw = getCreds()
           
                attempts += 1
            else:
                print('Too many invalid attempts. Try again later.')
                sys.exit('Exiting...')  
    
        
    ldapInfo = queryDomainControllers(queryUser=queryUser, queryGroup=queryGroup, verbose=verbose)

    if options.user:
        printLdapInfo(ldapInfo, output_format=out_format)
    
    
if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()        
