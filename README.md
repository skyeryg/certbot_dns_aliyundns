# Aliyun DNS Authenticator plugin for Certbot

A certbot dns plugin to obtain certificates using aliyun.


## Obtain Aliyun RAM AccessKey
[https://ram.console.aliyun.com/](https://ram.console.aliyun.com/)

And ensure your RAM account has `AliyunDNSFullAccess` permission.


## Install

```bash
git clone https://github.com/skyeryg/certbot-dns-aliyundns
cd certbot-dns-aliyundns
sudo python setup.py install
```

If you are using `certbot-auto`, you should run `virtualenv` first:

```bash
# CentOS 7
virtualenv --no-site-packages --python "python2.7" "/opt/eff.org/certbot/venv"
/opt/eff.org/certbot/venv/bin/python2.7 setup.py install
```

## Credentials File

```ini
certbot_dns_aliyundns:dns_aliyundns_access_key = 12345678
certbot_dns_aliyundns:dns_aliyundns_access_key_secret = 1234567890abcdef1234567890abcdef
```

```bash
chmod 600 /path/to/credentials.ini
```


## Obtain Certificates

```bash
certbot certonly -a certbot-dns-aliyundns \
    --certbot-dns-aliyundns-credentials /path/to/credentials.ini \
    -d example.com \
    -d "*.example.com"
```
