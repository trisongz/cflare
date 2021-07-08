import os
import requests
from datetime import datetime, timezone
from dataclasses import dataclass, field

from typing import List, Dict, Any, Optional
from dataclasses_json import dataclass_json
from dataclasses_json import Undefined

from ..utils import logger

timestamp = lambda: datetime.now(timezone.utc).isoformat('T')

class CFlareAuth:
    def __init__(self, api_user=None, api_key=None, api_token=None):
        self.user = api_user or os.environ.get('CFLARE_USER', os.environ.get('CLOUDFLARE_USER'))
        self.key = api_key or os.environ.get('CFLARE_KEY', os.environ.get('CLOUDFLARE_KEY'))
        self.token = api_token or os.environ.get('CFLARE_TOKEN', os.environ.get('CLOUDFLARE_TOKEN'))
        
    def update(self, api_user=None, api_key=None, api_token=None, **kwargs):
        self.user = api_user or self.user
        self.key = api_key or self.key
        self.token = api_token or self.token
        if kwargs:
            for k,v in kwargs.items():
                if k in self.__dict__:
                    self.__dict__[k] = v
    @property
    def headers(self):
        params = {
            'Content-Type': 'application/json'
        }
        if self.user and self.key:
            params['X-Auth-Email'] = self.user
            params['X-Auth-Key'] = self.key
        else:
            params['Authorization'] = 'Bearer ' + self.token
        return params

    @property
    def data(self):
        return {'CFLARE_USER': self.user, 'CFLARE_KEY': self.key, 'CFLARE_TOKEN': self.token}


@dataclass_json
@dataclass(frozen=True)
class CFlareAccount:
    id: str
    name: str


@dataclass_json
@dataclass(frozen=True)
class CFlareUser:
    id: str
    type: str
    email: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class CFlareZoneResponse:
    id: str
    name: str
    status: str
    paused: bool
    type: str
    development_mode: int
    name_servers: List[str]
    owner: Optional[CFlareUser] = None
    account: Optional[CFlareAccount] = None
    permissions: List[str] = None

    @property
    def zone_id(self):
        return self.id
    
    @property
    def domain_name(self):
        return self.name
    


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class CFlareRecordResponse:
    id: str
    name: Optional[str] = None
    type: Optional[str] = None
    zone_id: Optional[str] = None
    zone_name: Optional[str] = None
    content: Optional[str] = None
    proxiable: Optional[bool] = False
    proxied: Optional[bool] = False
    ttl: Optional[int] = 1
    locked: Optional[bool] = False
    meta: Optional[Dict[str, Any]] = None
    created_on: Optional[str] = field(metadata={'dataclasses_json': {'encoder': datetime.isoformat, 'decoder': datetime.fromtimestamp}}, default=None)
    modified_on: Optional[str] = field(metadata={'dataclasses_json': {'encoder': datetime.isoformat, 'decoder': datetime.fromtimestamp}}, default=None)

    @property
    def domain(self):
        return self.zone_name

    @property
    def subdomain(self):
        return self.name.replace(self.zone_name, '')[:-1]
    
    @property
    def full_name(self):
        return self.name

    @property
    def wildcard(self):
        return bool('*' in self.subdomain)
    
    @property
    def record(self):
        return self.content
    
    @property
    def address(self):
        return self.content
    
    @property
    def record_id(self):
        return self.id
    
    @property
    def record_type(self):
        return self.type
    
    @property
    def record_data(self):
        return {'type': self.type, 'content': self.content}
    
    def needs_update(self, ip_address: str):
        return self.content != ip_address
    


@dataclass_json
@dataclass(frozen=True)
class CFlarePoolOrigin:
    name: str
    address: str
    enabled: bool
    weight: float
    header: Dict[str, Any]
    healthy: bool
    failure_reason: str


@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class CFlarePoolResponse:
    id: str
    name: str
    description: str
    enabled: bool
    minimum_origins: int
    monitor: str
    check_regions: List[str]
    origins: List[CFlarePoolOrigin]
    notification_email: str
    notification_filter: Optional[Dict[str, Dict[str, bool]]] = None
    created_on: str = field(metadata={'dataclasses_json': {'encoder': datetime.isoformat, 'decoder': datetime.fromtimestamp}}, default=None)
    modified_on: str = field(metadata={'dataclasses_json': {'encoder': datetime.isoformat, 'decoder': datetime.fromtimestamp}}, default=None)
    load_shedding: Optional[Dict[str, Any]] = None

    @property
    def pool_id(self):
        return self.id
    
    @property
    def monitor_id(self):
        return self.monitor


@dataclass_json
@dataclass(frozen=True)
class CFlarePoolOriginStatus:
    healthy: bool
    failure_reason: str
    response_code: Optional[int] = None
    rtt: Optional[str] = None

    @property
    def response_time(self):
        if not self.rtt:
            return None
        return float(self.rtt.replace('ms', ''))

@dataclass_json
@dataclass(frozen=True)
class CFlarePoolRegionHealth:
    healthy: bool
    origins: List[Dict[str, CFlarePoolOriginStatus]]

    @property
    def status(self):
        res = {}
        for origin in self.origins:
            for k,v in origin.items():
                res[k] = v.healthy
        return res

    @property
    def health(self):
        res = {}
        for origin in self.origins:
            for k,v in origin.items():
                res[k] = 'healthy' if v.healthy else 'unhealthy'
        return res
    
    @property
    def total_healthy(self):
        return len([i for i in self.status.values() if i])

    @property
    def total_nodes(self):
        return len(self.health.values())

@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class CFlarePoolHealthResponse:
    pool_id: str
    pop_health: Dict[str, CFlarePoolRegionHealth]

    @property
    def status(self):
        return {k: v.status for k,v in self.pop_health.items()}

    @property
    def health(self):
        return {k: v.health for k,v in self.pop_health.items()}
    
    @property
    def percentage_healthy(self):
        return {k: v.total_healthy/v.total_nodes for k,v in self.pop_health.items()}
    



@dataclass_json(undefined=Undefined.EXCLUDE)
@dataclass
class CFlareMonitorResponse:
    id: str
    type: str
    description: str
    method: str
    path: str
    header: Dict[str, Any]
    port: int
    timeout: int
    interval: int
    expected_body: str
    expected_codes: str
    follow_redirects: bool
    allow_insecure: bool

    @property
    def monitor_id(self):
        return self.id


class CFlareRecord:
    def __init__(self, domain: str = None, subdomain: str = None, record_type: str = 'A', address: str = None, proxied: bool = False, ttl: int = 1, content: str = None, **kwargs):
        self.domain = domain or os.environ.get('CFLARE_DOMAIN', os.environ.get('CLOUDFLARE_DOMAIN'))
        self.subdomain = subdomain or os.environ.get('CFLARE_SUBDOMAIN', os.environ.get('CLOUDFLARE_SUBDOMAIN'))
        self.record_type = record_type or os.environ.get('CFLARE_RECORD', os.environ.get('CLOUDFLARE_RECORD'))
        self.address = address or os.environ.get('CFLARE_ADDRESS', os.environ.get('CLOUDFLARE_ADDRESS', self.host_public_ip))
        self.content = content or os.environ.get('CFLARE_CONTENT', os.environ.get('CLOUDFLARE_CONTENT'))
        self.ttl = ttl or int(os.environ.get('CFLARE_TTL', os.environ.get('CLOUDFLARE_TTL', 1)))
        self.proxied = proxied or bool(os.environ.get('CFLARE_PROXIED', os.environ.get('CLOUDFLARE_PROXIED', 'false')) in ['true', 'True', '1'])
        self.full_name = (self.subdomain + '.' +  self.domain) if self.subdomain else self.domain
        self.kwargs = kwargs
    
    def validate(self):
        for value in [self.domain, self.record_type, self.address]:
            if not value: raise ValueError

    @property
    def host_public_ip(self):
        return requests.get('https://ifconfig.me/ip').text
    
    @property
    def data(self):
        d = {'type': self.record_type, 'name': self.full_name, 'content': self.content or self.address, 'ttl': self.ttl, 'proxied': self.proxied}
        if self.kwargs.get('priority'):
            d['priority'] = self.kwargs['priority']
        return d


class MXRecords:
    def __init__(self, mx_data: Dict[str, int], domain: str = None, subdomain: str = None):
        self.records = [CFlareRecord(domain=domain, subdomain=subdomain, record_type='MX', content=mx, priority=priority) for mx, priority in mx_data.items()]


_gmx_records = {'aspmx.l.google.com': 1, 'alt1.aspmx.l.google.com': 5, 'alt2.aspmx.l.google.com': 5, 'alt3.aspmx.l.google.com': 10, 'alt4.aspmx.l.google.com': 10}

class GoogleMXRecords:
    def __init__(self, domain: str = None, subdomain: str = None, mx_data: Dict[str, int] = _gmx_records):
        mx = MXRecords(mx_data, domain, subdomain)
        self.records = mx.records


class CFlareAPI:
    def __init__(self, auth: CFlareAuth = CFlareAuth()):
        self.auth = auth
        self.sess = requests.session()
        self.sess.headers.update(self.auth.headers)

    def get_domain_records(self, domain_name=None, status='active', per_page=50, order='status', direction='desc', match='all', **kwargs):
        params = {'status': status, 'per_page': per_page, 'order': order, 'direction': direction, 'match': match}
        if domain_name: params['name'] = domain_name
        if kwargs: params.update(kwargs)
        resp = self.sess.get(self.domain_api_url, params=params).json()
        return CFlareZoneResponse.schema().load(resp['result'], many=True)
    
    def get_zone_records(self, zone_id: str, record_type: str = 'A', **kwargs):
        params = {'type': record_type}
        if kwargs: params.update(kwargs)
        resp = self.sess.get(self.get_zone_url(zone_id), params=params).json()
        return CFlareRecordResponse.schema().load(resp['result'], many=True)

    def create_record(self, zone_id: str, record: CFlareRecord = CFlareRecord()):
        resp = self.sess.post(self.get_zone_url(zone_id), params=record.data).json()
        return CFlareRecordResponse.from_dict(resp['result'])

    def update_record(self, zone_id: str , record_id: str, record: CFlareRecord = CFlareRecord()):
        resp = self.sess.put(self.get_record_url(zone_id, record_id), params=record.data).json()
        return CFlareRecordResponse.from_dict(resp['result'])
    
    def delete_record(self, zone_id, record_id, **kwargs):
        resp = self.sess.delete(self.get_record_url(zone_id, record_id)).json()
        return CFlareRecordResponse.from_dict(resp['result'])

    def get_lb_pools(self, monitor_id=None, **kwargs):
        if monitor_id or kwargs:
            params = {'monitor': monitor_id}
            if kwargs: params.update(kwargs)
        else:
            params = None
        resp = self.sess.get(self.load_balancer_pools_api_url, params=params).json()
        return CFlarePoolResponse.schema().load(resp['result'], many=True)
    
    def get_lb_monitors(self, **kwargs):
        resp = self.sess.get(self.load_balancer_monitors_api_url).json()
        return CFlareMonitorResponse.schema().load(resp['result'], many=True)
    
    def get_lb_health(self, pool_id, **kwargs):
        resp = self.sess.get(self.get_pool_health_url(pool_id)).json()
        print(resp)
        return CFlarePoolHealthResponse.from_dict(resp['result'])

    def sync(self, domain: str = None, subdomain: str = None, record_type: str = 'A', address: str = None, proxied: bool = False, **kwargs):
        record = CFlareRecord(domain, subdomain, record_type, address, proxied, **kwargs)
        record.validate()
        domain_records = self.get_domain_records(record.domain)[0]
        zone_records = self.get_zone_records(domain_records.zone_id)
        # check all records to match full name
        matched_records = [r for r in zone_records if r.full_name == record.full_name]
        if matched_records:
            matched = matched_records[0]
            if not matched.needs_update(record.address):
                logger.info(f'Record [{record.record_type}] {record.full_name} = {record.address} matches. Skipping Update.')
                return matched

            # update existing
            res = self.update_record(zone_id=domain_records.zone_id, record_id=record.record_id, record=record)
            logger.info(f'Updated Record [{res.record_type}] {res.full_name} = {res.record}. Sync complete.')
            return res
        
        # create record
        res = self.create_record(zone_id=domain_records.zone_id, record=record)
        logger.info(f'Created Record [{res.record_type}] {res.full_name} = {res.record}. Sync complete.')
        return res


    def desync(self, domain: str = None, subdomain: str = None, record_type: str = 'A', address: str = None, **kwargs):
        record = CFlareRecord(domain, subdomain, record_type, address, **kwargs)
        record.validate()
        domain_records = self.get_domain_records(record.domain)[0]
        zone_records = self.get_zone_records(domain_records.zone_id)
        # check all records to match full name
        matched_records = [r for r in zone_records if (r.full_name == record.full_name and r.address == record.address and r.record_type == record.record_type)]
        if not matched_records:
            logger.info(f'No Matches for Record [{record.record_type}] {record.full_name} = {record.address}. Passing')
            return
        matched = matched_records[0]
        logger.info(f'Removing Record [{matched.record_type}] {matched.full_name} = {matched.record}')
        res = self.delete_record(domain_records.zone_id, matched.record_id)
        logger.info(f'Record {res.id} deleted')
        return res

    @property
    def all_domains(self):
        domain_records = self.get_domain_records()
        return [d.domain_name for d in domain_records]

    @property
    def all_lb_status(self):
        pools = self.get_lb_pools()
        res = {}
        for pool in pools:
            res[pool.name] = {'id': pool.id, 'nodes': {}, 'timestamp': timestamp()}
            for origin in pool.origins:
                res[pool.name]['nodes'][origin.name] = {
                    'name': origin.name,
                    'enabled': origin.enabled,
                    'weight': origin.weight,
                    'address': origin.address,
                    'healthy': origin.healthy,
                    'status': origin.failure_reason,
                }
        return res

    @property
    def domain_api_url(self):
        return 'https://api.cloudflare.com/client/v4/zones'
    
    @property
    def zone_api_url(self):
        return 'https://api.cloudflare.com/client/v4/zones/[ZONEID]/dns_records'
    
    def get_zone_url(self, zone_id):
        return self.zone_api_url.replace('[ZONEID]', zone_id)
    
    @property
    def record_api_url(self):
        return 'https://api.cloudflare.com/client/v4/zones/[ZONEID]/dns_records/[RECORDID]'
    
    def get_record_url(self, zone_id, record_id):
        return self.record_api_url.replace('[ZONEID]', zone_id).replace('[RECORDID]', record_id)

    @property
    def load_balancer_api_url(self):
        return 'https://api.cloudflare.com/client/v4/user/load_balancers'
    
    @property
    def load_balancer_monitors_api_url(self):
        return 'https://api.cloudflare.com/client/v4/user/load_balancers/monitors'
    
    @property
    def load_balancer_pools_api_url(self):
        return 'https://api.cloudflare.com/client/v4/user/load_balancers/pools'
    
    @property
    def load_balancer_pool_health_api_url(self):
        return 'https://api.cloudflare.com/client/v4/user/load_balancers/pools/[POOLID]/health'
    
    def get_pool_health_url(self, pool_id):
        return self.load_balancer_pool_health_api_url.replace('[POOLID]', pool_id)
    
    @property
    def host_public_ip(self):
        return requests.get('https://ifconfig.me/ip').text


