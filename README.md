# caddy-maxmind-asn
Caddy v2 module to filter requests based on ASN.

## Installation

You can build Caddy by yourself by [installing xcaddy](https://github.com/caddyserver/xcaddy) and running:
```
xcaddy build --with github.com/lum8rjack/caddy-maxmind-asn
```

## Requirements 

To be able to use this module you will need to have a MaxMind GeoLite2 database, that can be downloaded for free
by creating an account. More information about this are available on the
[official website](https://dev.maxmind.com/geoip/geoip2/geolite2/).

You will specifically need the `GeoLite2-ASN.mmdb` file.

## Usage

You can use this module as a matcher to allow or block a set of Autonomous System Organization. The ASOs are non case-sensitive and will match as long as the ASN contains the provided matcher.

Example: Providing 'allow_asos amazon' will match on AMAZON and AMAZON-12


### Caddyfile

1. Allow access to the website only from ASNs associated with Amazon:
```
test.example.org {
  @myasn {
    maxmind_asn {
      db_path "/usr/share/MaxMind/GeoLite2-ASN.mmdb"
      allow_asos amazon
    }
  }

   file_server @myasn {
     root /var/www/html
   }
}
```

2. Deny access to the website from ASNs associated with Amazon:
```
test.example.org {
  @myasn {
    maxmind_asn {
      db_path "/usr/share/MaxMind/GeoLite2-ASN.mmdb"
      deny_asos amazon
    }
  }

   file_server @myasn {
     root /var/www/html
   }
}
```
