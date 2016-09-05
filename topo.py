__author__ = 'lnn'

import networkx as nx

def enum(**enums):
    return type('Enum', (), enums)

ModeType = enum(N=0, R=1, W=2, RW=3)

class Model:
    def __init__(self, switch=[], port=[], link=[], flow=[]):
        self.switch = switch
        self.port = port
        self.link = link
        self.flow = flow


class Port(object):
    def __init__(self, dpid, ofproto, port_no, hw_addr, name, mode=ModeType.RW):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto

        self.port_no = port_no
        self.hw_addr = hw_addr
        self.name = name
        self.mode = mode

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, hw_addr=%s, name=%s>' % \
            (self.dpid, self.port_no, self.hw_addr, self.name)


class Switch(object):
    def __init__(self, name):
        super(Switch, self).__init__()

        self.name = name
        self.ports = []


class Link(object):
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d


class OFPFlowStats:
    def __init__(self):
        super(OFPFlowStats, self).__init__()
        self.length = None
        self.table_id = None
        self.match = None
        self.duration_sec = None
        self.duration_nsec = None
        self.priority = None
        self.idle_timeout = None
        self.hard_timeout = None
        self.cookie = None
        self.packet_count = None
        self.byte_count = None
        self.actions = None

class ShortestPath:
    def __init__(self):

        # Execute shortest path logic, determine what polices
        # need to be installed and source and destination of the path
        self.match.self.in_port = 0
        self.match.ipv4_src = '10.0.0.1'
        self.match.ipv4_dst = '20.0.0.1'
        self.src = '9'
        self.dst = '5'

        ports_name = ['s1-eth1', 's1-eth2']
        self.model = initModel(ports_name)
        maxtry = 5
        i = 0
        while(i <= maxtry):
            try:
                self.resp = self.add_path()
            except ConflictError e:
                self.model = updateModel(ports_name, e.conflict_flow)
                self.lastError = e;
            if(self.resp != None):
                break;
            i = i + 1
        if(self.resp == None):
            if(self.lastError != None):
                raise self.lastError
            else:
                raise NoneResponseError

    def add_path(self):
        G = nx.Graph()
        for link in self.model.link:
            if not is_conflict(link, self.model.flow):
                G.add_edge(link.src, link.dst)
        path = nx.shortest_path(G, self.src, self.dst)
        # set up the mode of flow rules along the path, ModeType.N represents
        # other applications of low-level priority cannot read its rules to
        # avoid these applications achieving global network view through sending
        # down a quantity of malicious flow rules
        install(path, ModeType.N, self.match)