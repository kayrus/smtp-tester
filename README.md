# smtp-tester

A tool to run SMTP stress tests

## Help

```
Usage of smtp-tester:
  -debug
        show debug logs
  -from string
        Envelope from sender address
  -header-from string
        Header from sender address, if empty defaults to --from
  -max-mails uint
        Limit the amount of emails, 0 means no limit
  -password string
        SMTP server password
  -reuse-smtp
        Reuse SMTP connection
  -show-error
        show error type on auth failure
  -size uint
        Message size in bytes (default 30720)
  -smtp-host string
        SMTP server address
  -starttls
        whether to require StartTLS (default true)
  -subject string
        Email subject (default "hello")
  -threads uint
        Whether to run an infinite loop with an amount of threads
  -timeout uint
        Timeout in seconds (default 3)
  -to string
        Recipient address
  -username string
        SMTP server username
```

## Example

```sh
smtp-tester -max-mails 1000 \
  -from test@example.com \
  -to blackbox@example.com \
  -show-error \
  -smtp-host localhost:25 \
  -threads 100 \
  -username user \
  -password password \
  -size 10 \
  -timeout 30 \
  -starttls=false
```
