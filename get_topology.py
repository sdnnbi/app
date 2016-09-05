
from ryu.topology.api import get_host
import json
import logging
from ryu.app.wsgi import ControllerBase

LOG = logging.getLogger(__name__)


class TopologyControlle(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyControlle, self).__init__(req, link, data, **config)
        self.topology_api_app = data['topology_api_app']
        self._hosts()

    def _hosts(self):
        dpid = None
        hosts = get_host(self.topology_api_app, dpid)
        body = json.dumps([host.to_dict() for host in hosts])
        print('---------body-------')
        print(body)

