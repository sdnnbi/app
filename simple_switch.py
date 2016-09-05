# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.controller.handler import DEAD_DISPATCHER
from ryu.lib import hub
from ryu.topology.api import get_switch, get_link
from topo import *
from ryu.lib import mac


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self . datapaths  =  {}
        self . monitor_thread = hub . spawn(self . _monitor)
        hub.spawn(self.sent_policy)
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
            #print('----_monitor--flow--', len(self.flow))

    def sent_policy ( self ):

        hub . sleep ( 10 )
        self.get_model()

        #hub . sleep ( 10 )
        #print('---h1_ping_h2--100-')
        #self.h1_ping_h2()

    def _request_stats(self, datapath):
        self . logger . debug('send stats request: %016x ',  datapath . id)
        ofproto = datapath . ofproto
        parser = datapath . ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath, flags=0, table_id=0,
                    out_port=ofproto.OFPP_NONE, match=parser.OFPMatch())
        datapath . send_msg(req)

    @set_ev_cls(ofp_event . EventOFPFlowStatsReply,  MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self,  ev):
        body = ev . msg . body
        self . flows.setdefault(ev.msg.datapath, [])
        self . flows[ev.msg.datapath] = body

    def conflict_detection(self, datapath, match, actions):
        print('--conflict_detection---', datapath.id)
        if not (datapath in self.flows):
            print('-----', self.flows, len(self.flows))
            return None
        for flow in self.flows[datapath]:
            m = flow.match
            print('==============', match.in_port)
            #wc = datapath.ofproto.OFPFW_ALL
            if not (m.in_port is 0 or match.in_port is 0 or m.in_port == match.in_port):
                continue
            if not (m.dl_src == mac.DONTCARE or match.dl_src == mac.DONTCARE or m.dl_src == match.dl_src):
                continue
            if not (m.dl_dst == mac.DONTCARE or match.dl_dst == mac.DONTCARE or m.dl_dst == match.dl_dst):
                continue
            if not (m.dl_vlan == 0 or match.dl_vlan == 0 or m.dl_vlan == match.dl_vlan):
                continue
            if not (m.dl_vlan_pcp == 0 or match.dl_vlan_pcp == 0 or m.dl_vlan_pcp == match.dl_vlan_pcp):
                continue
            if not (m.dl_type == 0 or match.dl_type == 0 or m.dl_type == match.dl_type):
                continue
            if not (m.nw_tos == 0 or match.nw_tos == 0 or m.nw_tos == match.nw_tos):
                continue
            if not (m.nw_proto == 0 or match.nw_proto == 0 or m.nw_proto == match.nw_proto):
                continue
            if not (m.nw_src == 0 or match.nw_src == 0 or m.nw_src == match.nw_src):
                continue
            if not (m.nw_dst == 0 or match.nw_dst == 0 or m.nw_dst == match.nw_dst):
                continue
            if not (m.tp_src == 0 or match.tp_src == 0 or m.tp_src == match.tp_src):
                continue
            if not (m.tp_dst == 0 or match.tp_dst == 0 or m.tp_dst == match.tp_dst):
                continue
            for action in actions:
                for fa in flow.actions:
                    if fa.port == action.port:
                        self . logger . info ( ' %016x  %8x  %17s  %8x  %8d  %8d ' ,
                             datapath . id ,
                             m.in_port,  match.dl_dst,
                             action. port ,
                             flow . packet_count ,  flow . byte_count )
                        return flow
        self . logger . info ('-------no flow conflict-------')
        return None


    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        print('---------add_flow---------')
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))
        conflict_flow = self.conflict_detection(datapath,match,actions)
        if conflict_flow is not None:
            model, vmap = self.updateModel(datapath.id, conflict_flow)
            if len(model.switch) > 0:
                print("-----model: ", model.switch[0].name)
                print("-----model: ", model.switch[0].ports)
            for p in model.port:
                print(p)
                print(vmap[(model.switch[0], p)][1])
            return
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def updateModel(self, datapath_id, conflict_flow):
        switches = get_switch(self, None)
        links = get_link(self, None)
        vswitches=[]
        vports=[]
        vlinks=[]
        flow = [conflict_flow]
        vmap = {}
        ports_name = ['s1-eth1', 's1-eth2']

        for s in switches:
            vswitch = Switch("X")
            for p in s.ports:
                if p.name in ports_name:
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
                else:
                    if s.dp.id == datapath_id:
                        for conflict_action in conflict_flow.actions:
                            if conflict_action.port == p.port_no:
                                vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name, ModeType.R)
                                vports.append(vport)
                                vmap[(vswitch, vport)] = (s, p)
            vswitch.ports = vports
            vswitches.append(vswitch)
        for l in links:
            vlink = Link(l.src, l.dst)
            vlinks.append(vlink)
        model = Model(vswitches, vports, vlinks, flow)

        return model, vmap

    def initModel(self):
        switches = get_switch(self, None)
        links = get_link(self, None)
        vswitches=[]
        vports=[]
        vlinks=[]
        flow = []
        vmap = {}
        ports_name = ['s1-eth1', 's1-eth2']

        for s in switches:
            vswitch = Switch("X")
            for p in s.ports:
                if p.name in ports_name:
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
            vswitch.ports = vports
            vswitches.append(vswitch)
        for l in links:
            vlink = Link(l.src, l.dst)
            vlinks.append(vlink)
        model = Model(vswitches, vports, vlinks, flow)

        return model, vmap

    def update_big_switch(self, datapath_id, conflict_flow):
        switches = get_switch(self, None)
        links = get_link(self, None)
        vswitches=[]
        vports=[]
        vlinks=[]
        flow = [conflict_flow]
        vmap = {}
        ports_name = ['s1-eth1', 's2-eth2']

        vswitch = Switch("X")

        for s in switches:
            for p in s.ports:
                if p.name in ports_name:
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
                else:
                    if s.dp.id == datapath_id:
                        for conflict_action in conflict_flow.actions:
                            if conflict_action.port == p.port_no:
                                vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name, ModeType.R)
                                vports.append(vport)
                                vmap[(vswitch, vport)] = (s, p)
            vswitch.ports = vports
            vswitches.append(vswitch)
        for l in links:
            vlink = Link(l.src, l.dst)
            vlinks.append(vlink)
        model = Model(vswitches, vports, vlinks, flow)

        return model, vmap

    def big_switch(self):
        switches = get_switch(self, None)
        links = get_link(self, None)
        vswitches=[]
        vports=[]
        vlinks=[]
        flow = []
        vmap = {}
        ports_name = ['s1-eth1', 's2-eth2']

        vswitch = Switch("X")

        for s in switches:
            for p in s.ports:
                if p.name in ports_name:
                    vport = Port(p.dpid, p._ofproto, p.port_no, p.hw_addr,p. name)
                    vports.append(vport)
                    vmap[(vswitch, vport)] = (s, p)
            vswitch.ports = vports
            vswitches.append(vswitch)
        for l in links:
            vlink = Link(l.src, l.dst)
            vlinks.append(vlink)
        model = Model(vswitches, vports, vlinks, flow)

        return model, vmap

    def get_model(self):
        print('-------get_model---------')
        model, vmap = self.initModel()
        if len(model.switch) > 0:
            print("-----model: ", model.switch[0].name)
            print("-----model: ", model.switch[0].ports)
        for p in model.port:
            print(p)
            print(vmap[(model.switch[0], p)][1])

    def pingall_flow(self, buffer_id, data, in_port):
        switches = get_switch(self, None)
        for s in switches:
            dp = s.dp
            if dp.id==1:
                out = s.ports[1]
                out_port = out.port_no
                actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=buffer_id, in_port=s.ports[0].port_no,
                    actions=actions, data=data)
                dp.send_msg(out)
            if dp.id==2:
                out = s.ports[0]
                out_port = out.port_no
                actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=buffer_id, in_port=s.ports[1].port_no,
                    actions=actions, data=data)
                dp.send_msg(out)
            if dp.id==3:
                actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_IN_PORT)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=buffer_id, in_port=in_port,
                    actions=actions, data=data)
                dp.send_msg(out)


    def add_ping_flow(self, dp, in_port, out_port):
        print('---add_ping_flow----',dp.id)
        ofproto = dp.ofproto
        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
        match = dp.ofproto_parser.OFPMatch(
            in_port=in_port)
        conflict_flow = self.conflict_detection(dp,match,actions)
        if conflict_flow is not None:
            model, vmap = self.updateModel(dp.id, conflict_flow)
            if len(model.switch) > 0:
                print("-----model: ", model.switch[0].name)
                print("-----model: ", model.switch[0].ports)
            for p in model.port:
                print(p)
                print(vmap[(model.switch[0], p)][1])
            return
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)

    def h1_ping_h2(self):
        print('-----1----')
        switches = get_switch(self, None)
        print('-----2----')
        for s in switches:
            dp = s.dp
            if dp.id==1:
                self.add_ping_flow(dp, s.ports[0].port_no, s.ports[2].port_no)
                self.add_ping_flow(dp, s.ports[1].port_no, s.ports[0].port_no)
            if dp.id==2:
                self.add_ping_flow(dp, s.ports[0].port_no, s.ports[1].port_no)
                self.add_ping_flow(dp, s.ports[1].port_no, s.ports[0].port_no)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        print("test-----")
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

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

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        #self.pingall_flow(msg.buffer_id, data, msg.in_port)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


class topo:
    def __init__(self, switch=[], port=[], link=[]):
        self.switch = switch
        self.port = port
        self.link = link

    def getTopo(self, match=[]):
        for m in match:
            for s in self.filterSwitchFromMatch(m):
                if m.in_port==None:
                    map[s] = s
                else:
                    map[(s, m.in_port)] = (s, m.in_port)
                    #mode[(s, m.in_port)]
        return map

    def filterSwitchFromMatch(self, match):
        return [s for s in self.switch if s.ports[match.in_port]==None]
