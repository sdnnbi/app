# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.mac import haddr_to_str
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.lib import hub
from ryu.topology.api import get_switch, get_link
from topo import *
import time


class SimpleSwitchStp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchStp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        self . datapaths = {}
        self . monitor_thread = hub . spawn(self . _monitor)
        self . flows = {}

    @set_ev_cls(ofp_event . EventOFPStateChange,
                [MAIN_DISPATCHER,  DEAD_DISPATCHER])
    def _state_change_handler(self,  ev):
        datapath = ev . datapath
        if ev . state == MAIN_DISPATCHER:
            if not datapath . id in self . datapaths:
                self . logger . debug('register datapath: %016x ',  datapath . id)
                self . datapaths[datapath . id] = datapath
        elif ev . state == DEAD_DISPATCHER:
            if datapath . id in self . datapaths:
                self . logger . debug('unregister datapath: % 016x ',  datapath . id)
                del self . datapaths[datapath . id]

    def _monitor(self):
        while True:
            for dp in self . datapaths . values():
                self . _request_stats(dp)
            hub . sleep(10)
            #print(self.flows)
            self.initModel()

    def _request_stats(self, datapath):
        self . logger . debug('send stats request: %016x ',  datapath . id)
        ofproto = datapath . ofproto
        parser = datapath . ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath, flags=0, table_id=0,
                    out_port=ofproto.OFPP_NONE, match=parser.OFPMatch())
        datapath . send_msg(req)

    def initModel(self):
        switches = get_switch(self, None)
        links = get_link(self, None)
        vswitches = []
        vports = []
        vp = []
        vlinks = []
        flow = []
        vmap = {}
        pod = 4

        for s in switches:
            dpid = int(s.dp.id)
            if dpid < 100:
                if (dpid-1) % (pod/2) == 0:
                    vswitch = Switch('core'+str(dpid))
                    for p in s.ports:
                        vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                        vports.append(vport)
                        vp.append(vport)
                        vmap[(vswitch, vport)] = [(s, p)]
                else:
                    i = 0
                    for p in s.ports:
                        vmap[(vswitch, vp[i])].append((s, p))
                        i += 1
                    if dpid % (pod/2) == 0:
                        vswitch.ports = vp
                        vp = []
                        vswitches.append(vswitch)
            else:
                vswitch = Switch(str(dpid))
                for p in s.ports:
                    vswitch = Switch(str(dpid))
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vp.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
                vswitch.ports = vp
                vp = []
                vswitches.append(vswitch)
        for l in links:
            vlink = Link(l.src, l.dst)
            vlinks.append(vlink)
            print(vlink.src, '->', vlink.dst)
        model = Model(vswitches, vports, vlinks, flow)
        print('-------get_model---------')
        for s in model.switch:
            print("-----model: ", s.name)
            print("-----model: ", s.ports)
        start = time.clock()
        flag = False
        for vs in vswitches:
            for vp in vs.ports:
                try:
                    int(vs.name)
                except ValueError as e:
                    self.logger.info("hehe,, %s", vs.name)
                    if isinstance(vmap[(vs, vp)], list):
                        s, p = vmap[(vs, vp)][0]
                        if s.dp.id == 1:
                            flag = True
                            break
            if flag:
                vswitch = Switch('update'+str(dpid))
                vports = []
                for vp in vs.ports:
                    s, p = vmap[(vs, vp)].pop(0)
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
                vswitch.ports = vports
                flag = False
        end = time.clock()
        for s in vswitches:
            print("-----vswitches: ", s.name)
            print("-----vswitches: ", s.ports)
        print('start time: ', start)
        print('end time: ', end)
        print('run time: ', (end-start))

    @set_ev_cls(ofp_event . EventOFPFlowStatsReply,  MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self,  ev):
        body = ev . msg . body
        self . flows.setdefault(ev.msg.datapath, [])
        self . flows[ev.msg.datapath] = body

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s",
                          dpid, haddr_to_str(src), haddr_to_str(dst),
                          msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            del self.mac_to_port[dp.id]
        self.delete_flow(dp)

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
