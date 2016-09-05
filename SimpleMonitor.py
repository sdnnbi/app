

from  ryu.app  import  simple_switch
from  ryu.controller  import  ofp_event
from  ryu.controller.handler  import  MAIN_DISPATCHER ,  DEAD_DISPATCHER
from  ryu.controller.handler  import  set_ev_cls
from  ryu.lib  import  hub


class  SimpleMonitor ( simple_switch . SimpleSwitch ):

    def  __init__ ( self ,  * args ,  ** kwargs ):
        super ( SimpleMonitor ,  self ) . __init__ ( * args ,  ** kwargs )
        self . datapaths  =  {}
        self . monitor_thread  =  hub . spawn ( self . _monitor )

    @set_ev_cls ( ofp_event . EventOFPStateChange ,
                [ MAIN_DISPATCHER ,  DEAD_DISPATCHER ])
    def  _state_change_handler ( self ,  ev ):
        datapath  =  ev . datapath
        if  ev . state  ==  MAIN_DISPATCHER :
            if  not  datapath . id  in  self . datapaths :
                self . logger . debug ( 'register datapath: %016x ' ,  datapath . id )
                self . datapaths [ datapath . id ]  =  datapath
        elif  ev . state  ==  DEAD_DISPATCHER :
            if  datapath . id  in  self . datapaths :
                self . logger . debug ( 'unregister datapath: % 016x ' ,  datapath . id )
                del  self . datapaths [ datapath . id ]

    def  _monitor ( self ):
        while  True :
            for  dp  in  self . datapaths . values():
                self . _request_stats ( dp )
            hub . sleep ( 10 )

    def  _request_stats ( self ,  datapath ):
        self . logger . debug ( 'send stats request: %016x ' ,  datapath . id )
        ofproto  =  datapath . ofproto
        parser  =  datapath . ofproto_parser

        req  =  parser . OFPFlowStatsRequest ( datapath, flags=0, table_id=0,
                 out_port=ofproto.OFPP_NONE, match=parser.OFPMatch())
        datapath . send_msg ( req )

    @set_ev_cls ( ofp_event . EventOFPFlowStatsReply ,  MAIN_DISPATCHER )
    def  _flow_stats_reply_handler ( self ,  ev ):
        body  =  ev . msg . body
        self . logger . info(body)
        self . logger . info ( 'datapath '
                         'in-port eth-dst '
                         'out-port packets bytes' )
        self . logger . info ( '---------------- '
                         ' -------- ----------------- '
                         '-------- -------- ------- -' )
        print(body[0]. match)
        for  stat  in  sorted ([ flow  for  flow  in  body],
                           key = lambda  flow :  ( flow . match.in_port,
                                             flow . match.dl_dst)):
            self . logger . info ( ' %016x  %8x  %17s  %8x  %8d  %8d ' ,
                             ev . msg . datapath . id ,
                             stat . match.in_port,  stat . match.dl_dst,
                             stat . actions [ 0 ] . port ,
                             stat . packet_count ,  stat . byte_count )
            #print(stat . match.dl_dst.decode('utf8'))
            #print(stat . match.dl_dst.encode('utf-8'))
            #print('\x01\x80\xc2\x00\x00\x0e'.encode('latin1'))
