FROM certbot/certbot

COPY . src/certbot-dns-aliyundns

RUN pip install --no-cache-dir --editable src/certbot-dns-aliyundns
