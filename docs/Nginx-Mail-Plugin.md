The original implementation of nauthilus was developed to work as an authentication server for Nginx. Therefor the
protocol is still working and valid.

Here are some real life examples on how to integrate nauthilus with Nginx:

```nginx
server_name mail.example.test;

auth_http http://127.0.0.1:9080/mail/nginx;
auth_http_pass_client_cert on;

proxy_pass_error_message on;

ssl_certificate some-cert.pem;
ssl_certificate_key some-key.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_verify_client optional;
ssl_client_certificate some-ca-root-cert.pem;

resolver 127.0.0.1;

smtp_capabilities "SIZE 104857600" ENHANCEDSTATUSCODES 8BITMIME DSN CHUNKING;
imap_capabilities "IMAP4rev1" "LITERAL+" "SASL-IR" "LOGIN-REFERRALS" "ID" "ENABLE" "IDLE" "NAMESPACE";

server {
    listen 127.0.0.1:465 ssl;
    listen [::1]:465 ssl;
    # Add other external IPs
    protocol smtp;
    xclient on;
    smtp_auth login plain;
    auth_http_header X-Auth-Port "465";
    error_log /var/log/nginx/smtp.log info;
}

server {
    listen 127.0.0.1:587;
    listen [::1]:587;
    # Add other external IPs
    protocol smtp;
    xclient on;
    smtp_auth login plain;
    starttls on;
    auth_http_header X-Auth-Port "587";
    error_log /var/log/nginx/smtp.log info;
}

server {
    listen 127.0.0.1:143;
    listen [::1]:143;
    # Add other external IPs
    protocol imap;
    proxy_protocol on;
    imap_auth login plain;
    starttls on;
    auth_http_header X-Auth-Port "143";
    error_log /var/log/nginx/imap.log info;
}

server {
    listen 127.0.0.1:993 ssl;
    listen [::1]:993 ssl;
    # Add other external IPs
    protocol imap;
    proxy_protocol on;
    imap_auth login plain;
    auth_http_header X-Auth-Port "993";
    error_log /var/log/nginx/imap.log info;
}
```