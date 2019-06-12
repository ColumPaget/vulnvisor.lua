# SYNOPSIS

vulnvisor.lua pulls rss feeds from the bugtraq mailing-list, the NIST National Vulnerability Database and the security-focus newsfeed. It displays entries in these feeds that match a list of keywords given on the commandline, and can optionally send output in an email to a single email address. vulnvisor.lua can use the mail, mutt or sendmail programs to dispatch mail.

vulnvisor.lua requires libUseful and libUseful-lua to be installed.

# USAGE
```
vulnadvisor.lua <options> <keyword> <keyword> ...
```

# OPTIONS
```
  -t  <email>          Address to send report to
  -to <email>          Address to send report to
  -f  <email>          Sender address for email
  -from   <email>      Sender address for email
  -sender <email>      Sender address for email
  -?                   This help
  -h                   This help
  -help                This help
  --help               This help
```

# EXAMPLES
```
Print all items in feeds:              'lua vulnvisor.lua'
Print items with keyword 'android':    'lua vulnvisor.lua' android
Mail items with keyword 'android':     'lua vulnvisor.lua' -to me@somewhere.com android
Print items, multiple keywords:        'lua vulnvisor.lua android linux firefox cisco'
```
