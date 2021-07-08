
import os
import typer
from typing import Any, List, Optional, Tuple
from cflare.utils import logger, save_config, cflare_config
from cflare.lib import CFlareAuth, CFlareAPI, CFlareRecord

cli = typer.Typer()

auth_app = typer.Typer()
cli.add_typer(auth_app, name='auth')

records_app = typer.Typer()
cli.add_typer(records_app, name='records')

sync_app = typer.Typer()
cli.add_typer(sync_app, name='sync')

lb_app = typer.Typer()
cli.add_typer(lb_app, name='lb')


@auth_app.command()
def run_auth(email: str = typer.Argument(None, help="Cloudflare API User"), key: str = typer.Argument(None, help="Cloudflare API Key"), token: str = typer.Argument(None, help="Cloudflare API Token")):
    auth = CFlareAuth(api_user=email, api_key=key, api_token=token)
    logger.info(f'Saving CFlare Config to {cflare_config}')
    save_config(auth.data)

@sync_app.command()
def run_sync(domain: str = typer.Argument(None, help="Domain"), subdomain: str = typer.Argument(None, help="Subdomain"), record_type: str = typer.Argument('A', help="DNS Record Type"), content: str = typer.Argument(None, help="DNS Record Content"), proxied: bool = typer.Argument(False, help="Enable Proxied"), ttl: int = typer.Argument(1, help="Record TTL"), priority: int = typer.Argument(None, help="Record Priority")):
    api = CFlareAPI()
    _ = api.sync(domain, subdomain, record_type, proxied=proxied, content=content, priority=priority, ttl=ttl)

@lb_app.command('status')
def get_lb_status():
    api = CFlareAPI()
    lbs = api.all_lb_status
    for lb, data in lbs.items():
        lb_style = typer.style(lb, fg=typer.colors.BLUE, bold=True)
        lb_name = 'Load Balancer: ' + lb_style + ' | ID: ' + data['id'] + ' | Nodes: ' + len(data['nodes']) + ' | Timestamp: ' + data['timestamp']
        typer.echo(lb_name)
        for node, info in data['nodes'].items():
            node_style = typer.style(node, fg=(typer.colors.GREEN if info['healthy'] else typer.colors.RED) , bold=True)
            node_name = 'Node: ' + node_style
            typer.echo(node_name)
            for key in ['address', 'healthy', 'status', 'weight']:
                typer.echo(f' - {key.capitalize()} = {info[key]}')


if __name__ == "__main__":
    cli()