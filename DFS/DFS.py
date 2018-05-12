import logging
import struct
import networkx as nx
import copy

from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.base.app_manager import lookup_service_brick
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.topology.switches import LLDPPacket


from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import constants
import time

CONF = cfg.CONF


class DynamicFlowSteering(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    WEIGHT_MODEL = {'hop': 'weight', 'delay': "delay"}

    def __init__(self, *args, **kwargs):
        super(DynamicFlowSteering, self).__init__(*args, **kwargs)
        self.name = 'DFS'
        self.topology_api_app = self
        self.datapaths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]
        self.access_table = {}  # {(sw,port) :[host1_ip]}
        self.access_ports = {}  # dpid->port_num
        self.switch_port_table = {}  # dpip->port_num
        self.interior_ports = {}  # dpid->port_num
        self.link_to_port = {}  # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.graph = nx.DiGraph()
        self.shortest_paths = None
        # Start a green thread to discover network resource.
        self.discover_thread = hub.spawn(self.topology_discover)
        self.sw_module = lookup_service_brick('switches')
        self.echo_latency = {}
        self.measure_thread = hub.spawn(self.latency_detector)


    def arp_forwarding(self, msg, src_ip, dst_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,ofproto.OFPP_CONTROLLER,out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def get_host_location(self, host_ip):
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")


    #Gets the shortest paths and forwards them into switch flow tables
    def forward_shortest_paths(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                path = self.get_path(src_sw, dst_sw, weight=self.weight)
                self.logger.info("Path from source %s to destination %s: %s" % (ip_src, ip_dst, path))
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                self.install_flow(self.datapaths,self.link_to_port,self.access_table, path,flow_info, msg.buffer_id, msg.data)
        return


    #get pair of src and dst switches
    def get_sw(self, dpid, in_port, src, dst):
        src_switch = dpid
        dst_switch = None

        src_location = self.get_host_location(src)
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_switch = src_location[0]
            else:
                return None

        dst_location = self.get_host_location(dst)
        if dst_location:
            dst_switch = dst_location[0]

        return src_switch, dst_switch

    #get path based on weight--------------
    def get_path(self, src, dst, weight):
        shortest_paths = self.shortest_paths
        graph = self.graph

        if weight == self.WEIGHT_MODEL['hop']:
            return shortest_paths.get(src).get(dst)[0]
        elif weight == self.WEIGHT_MODEL['delay']:
            # If paths existed, return it, else calculate it and save it.
            try:
                paths = shortest_paths.get(src).get(dst)
                return paths[0]
            except:
                paths = self.k_shortest_paths(graph, src, dst,
                                                        weight=weight)

                shortest_paths.setdefault(src, {})
                shortest_paths[src].setdefault(dst, paths)
                return paths[0]

    #install flow
    def install_flow(self, datapaths, link_to_port, access_table, path, flow_info, buffer_id, data=None):
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i - 1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i + 1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
        if len(path) > 1:
            # the last flow entry: tor -> host
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]

            dst_port = self.get_port(flow_info[2], access_table)
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # the first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath
        else:
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    ########get path

    def k_shortestpaths_from_src_to_dst(self, graph, src, dst, weight='weight', k=1):

        generator = nx.shortest_simple_paths(graph, source=src,
                                             target=dst, weight=weight)
        shortest_paths = []
        try:
            for path in generator:
                if k <= 0:
                    break
                shortest_paths.append(path)
                k -= 1
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))

    def get_K_shortest_paths(self, graph, weight='weight', k=1):
        _graph = copy.deepcopy(graph)
        paths = {}

        # Find ksp in graph.
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src] for i in xrange(k)]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.k_shortestpaths_from_src_to_dst(_graph, src, dst,
                                                        weight=weight, k=k)
        return paths


    ######Install flow

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                src_dpid, dst_dpid))
            return None

    #build a flow
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=15, hard_timeout=60)

    #add flow to datapath
    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    #### latency/delay measurement starts from here.
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def latency_detector(self):
        while CONF.weight == 'delay':
            self.sending_echo_request()
            self.measure_link_latency()
            self.shortest_paths = {}
            self.logger.debug("Refresh the shortest_paths")
            self.show_delay_statis()
            hub.sleep(constants.DELAY_DETECTING_PERIOD)

     # send echo request on to the datapaths.
    def sending_echo_request(self):
        for each_datapath in self.datapaths.values():
            parser = each_datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(each_datapath, data="%.12f" % time.time())
            each_datapath.send_msg(echo_req)
            hub.sleep(constants.sending_echo_request_interval)

    # Get the latency of link by noting the timestamp of echo reply and timestamp in packet data
    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def handle_echo_reply(self, ev):
        timestamp_present = time.time()
        try:
            latency = timestamp_present - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return


    def get_link_latency(self, src, dst):
        try:
            lldp_forward_delay = self.graph[src][dst]['lldpdelay']
            lldp_reverse_delay = self.graph[dst][src]['lldpdelay']
            src_switch_latency = self.echo_latency[src]
            dst_switch_latency = self.echo_latency[dst]

            delay = (lldp_forward_delay + lldp_reverse_delay - src_switch_latency - dst_switch_latency) / 2
            return max(delay, 0)
        except:
            return float('inf')

    #calculate link delay and save it in graph data structure
    def measure_link_latency(self):
        for src in self.graph:
            for dst in self.graph[src]:
                if src == dst:
                    self.graph[src][dst]['delay'] = 0
                    continue
                delay = self.get_link_latency(src, dst)
                self.graph[src][dst]['delay'] = delay


    #parse the incoming lldp packet and get the lldp delay of the path
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_lldp_packet(self, ev):
        msg = ev.msg
        try:
            src_dpid, src_port_no, timestamp = LLDPPacket.lldp_parse(msg.data)
            dpid = msg.datapath.id
            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')

            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    delay = self.sw_module.ports[port].delay
                    self.graph[src_dpid][dpid]['lldpdelay'] = delay

        except LLDPPacket.LLDPUnknownFormat as e:
            return

    def show_delay_statis(self):
        if constants.TOSHOW :
            self.logger.info("\nLink Latency Measurement from a source to destination")
            self.logger.info("---------------------------------------------------------------")
            for src in self.graph:
                for dst in self.graph[src]:
                    delay = self.graph[src][dst]['delay']
                    self.logger.info("Delay between %s and %s is %s" % (src, dst, delay))



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)






    #we learn access_table by ARP.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handling_incoming_packets(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        packt = packet.Packet(msg.data)
        arp_pkt = packt.get_protocol(arp.arp)
        ip_pkt = packt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            if len(packt.get_protocols(ethernet.ethernet)):
                eth_type = packt.get_protocols(ethernet.ethernet)[0].ethertype
                self.forward_shortest_paths(msg, eth_type, ip_pkt.src, ip_pkt.dst)


    #push access host info into access table
    def register_access_info(self, dpid, in_port, ip, mac):

        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return



    #####topology discover starts from here
    def topology_discover(self):
        i = 0
        while True:
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(constants.DISCOVERY_PERIOD)
            i = i + 1



    # List the event list should be listened.
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    ##get topology to calculate the shortest paths using the topo information from topology API
    @set_ev_cls(events)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        links_info = get_link(self.topology_api_app, None)

        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

        self.switches = self.switch_port_table.keys()

        for link in links_info:
            src_switch = link.src
            dst_switch = link.dst
            self.link_to_port[(src_switch.dpid, dst_switch.dpid)] = (src_switch.port_no, dst_switch.port_no)

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)


        for each_switch in self.switch_port_table:
            all_port_table = self.switch_port_table[each_switch]
            interior_port = self.interior_ports[each_switch]
            self.access_ports[each_switch] = all_port_table - interior_port

        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in self.link_to_port.keys():
                    self.graph.add_edge(src, dst, weight=1)

        self.shortest_paths = self.get_K_shortest_paths(self.graph, weight='weight', k=CONF.k_paths)

