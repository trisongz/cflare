import os
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
warnings.filterwarnings('ignore', message='RequestsDependencyWarning')


cflare_root = os.path.abspath(os.path.dirname(__file__))
cflare_config = os.path.join(cflare_root, 'config.json')

from . import utils
from .utils import save_config

from . import lib
from .lib import MXRecords, GoogleMXRecords, CFlareRecord
from .lib import CFlareAuth, CFlareAPI