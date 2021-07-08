# cflare [WIP]
 Pythonic Cloudflare Ops

Making Cloudflare a little easier to work with in Python

Most Objects returned from the API are Dataclass Objects, allowing easier manipulation and accessing properties.

### Installation

Dependencies: `requests`, `typer`, `dataclasses-json`

```bash
pip install --upgrade cflare
```

### Environment Variables

**Authentication**
- API User: `CFLARE_USER`, `CLOUDFLARE_USER`
- API Key: `CFLARE_KEY`, `CLOUDFLARE_KEY`
- API Token: `CFLARE_TOKEN`, `CLOUDFLARE_TOKEN`

**Records**
_Important Note:_ Content takes priority over IP Address due to how default value is created. 

- Domain Name: `CFLARE_DOMAIN`, `CLOUDFLARE_DOMAIN`
- Subdomain Name: `CFLARE_SUBDOMAIN`, `CLOUDFLARE_SUBDOMAIN`
- Record Type: `CFLARE_RECORD`, `CLOUDFLARE_RECORD`, `[Default = 'A']`
- IP Address: `CFLARE_ADDRESS`,  `CLOUDFLARE_ADDRESS`, `[Default = Host IP Address]`
- Content: `CFLARE_CONTENT`, `CLOUDFLARE_CONTENT`
- TTL: `CFLARE_TTL`, `CLOUDFLARE_TTL`, `[Default = 1 or Auto]`
- Proxied: `CFLARE_PROXIED`, `CLOUDFLARE_PROXIED`,  `[Default = False]`


### Quick Start CLI
```bash
cflare auth --email user@email.com --key supersecureapikey

# This will sync the Host VM's Public IP Address to A Record app.mydomain.com = 123.123.123 [VM Public IP]
cflare sync --domain mydomain.com --subdomain app
```

### Quick Start API
```python
from cflare import CFlareAPI, CFlareAuth, save_config


# Auth: Optional.
## Save Auth Explicitly. Will be reloaded next time around.
auth = CFlareAuth(api_user='', api_key='') 
save_config(auth.data)

## Pass Auth to the API Explicitly
cfapi = CFlareAPI(auth)

# Or skip the above steps and have it be picked up from environment variables
cfapi = CFlareAPI()

domains = cfapi.all_domains
# ['domain1.com', 'domain2.com'...]

# Pass params explicitly
res = cfapi.sync(domain='', subdomain='', **config)

# Or call and have it be picked up by environment variables
res = cfapi.sync()

```