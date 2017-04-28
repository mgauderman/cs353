from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ofproto_v1_0

from topology import load_topology
import networkx as nx

# This function takes as input a networkx graph. It then computes
# the minimum Spanning Tree, and returns it, as a networkx graph.
def compute_spanning_tree(G):

	# The Spanning Tree of G
	if len(G.nodes()) == 0:
		return G	
		
	visited = set() #will hold whether a node has been visited yet
	node_list = [G.nodes()[0]] #holds the nodes in order for which to visit

	ST = nx.Graph()
	ST.add_node(G.nodes()[0])

	visited.add(G.nodes()[0])

	# implement BFS by adding neighbors, but never adding more than once
	# also pop from back so it traverses one path all the way
	while node_list: #keep going until all nodes have been visited 
		cur = node_list.pop(0) #pop first thing for proximity
		for next_to in G.neighbors(cur):
			if next_to not in visited: #helps to avoid loops
				visited.add(next_to)

				ST.add_node(next_to) #make new node
				ST.add_edge(cur, next_to) #create edge
				
				node_list.append(next_to) #queue node to check 
						      #neighbors for future
	for each in ST:
		ST.node[each] = G.node[each].copy()
	ST.graph = G.graph.copy()

	return ST
		
    	#ST = nx.minimum_spanning_tree(G) -> old implementation

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

	self.mac_to_port = {}

        # Load the topology
        topo_file = 'topology.txt'
        self.G = load_topology(topo_file)

        # For each node in the graph, add an attribute mac-to-port
        for n in self.G.nodes():
            self.G.add_node(n, mactoport={})

        # Compute a Spanning Tree for the graph G
        self.ST = compute_spanning_tree(self.G)

        print self.get_str_topo(self.G)
        print self.get_str_topo(self.ST)

    # This method returns a string that describes a graph (nodes and edges, with
    # their attributes). You do not need to modify this method.
    def get_str_topo(self, graph):
        res = 'Nodes\tneighbors:port_id\n'

        att = nx.get_node_attributes(graph, 'ports')
        for n in graph.nodes_iter():
            res += str(n)+'\t'+str(att[n])+'\n'

        res += 'Edges:\tfrom->to\n'
        for f in graph:
            totmp = []
            for t in graph[f]:
                totmp.append(t)
            res += str(f)+' -> '+str(totmp)+'\n'

        return res

    # This method returns a string that describes the Mac-to-Port table of a
    # switch in the graph. You do not need to modify this method.
    def get_str_mactoport(self, graph, dpid):
        res = 'MAC-To-Port table of the switch '+str(dpid)+'\n'

        for mac_addr, outport in graph.node[dpid]['mactoport'].items():
            res += str(mac_addr)+' -> '+str(outport)+'\n'

        return res.rstrip('\n')

    @set_ev_cls(EventSwitchEnter)
    def _ev_switch_enter_handler(self, ev):
        print('enter: %s' % ev)

    @set_ev_cls(EventSwitchLeave)
    def _ev_switch_leave_handler(self, ev):
        print('leave: %s' % ev)

    def add_flow(self, datapath, in_port, dst, actions):
	ofproto = datapath.ofproto

	match = datapath.ofproto_parser.OFPMatch(
		in_port=in_port, dl_dst=haddr_to_bin(dst))
	
	mod = datapath.ofproto_parser.OFPFlowMod(
		datapath=datapath, match=match, cookie=0,
		command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
		priority=ofproto.OFP_DEFAULT_PRIORITY,
		flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
	datapath.send_msg(mod)

    def get_neighbors(self, dpid, graph):
	neighbor_list = [graph.node[dpid]['ports']['host']]
	for neighbor in graph[dpid]:
		neighbor_list.append(graph.node[dpid]['ports'][str(neighbor)])
	return neighbor_list

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
	msg = ev.msg
	datapath = msg.datapath
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser

	pkt = packet.Packet(msg.data)
	eth = pkt.get_protocol(ethernet.ethernet)

	if eth.ethertype == ether_types.ETH_TYPE_LLDP:
		# ignore lldp packet
		return
	dst = eth.dst
	src = eth.src

	dpid = datapath.id
	self.mac_to_port.setdefault(dpid, {})

	self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
	
	#learn a mac address to avoid FLOOD next time.
	self.mac_to_port[dpid][src] = msg.in_port

	if dst in self.mac_to_port[dpid]:
		out_port = self.mac_to_port[dpid][dst]
		actions = [parser.OFPActionOutput(out_port)]
		self.add_flow(datapath, msg.in_port, dst, actions)

		data = None
		
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out_packet = parser.OFPPacketOut(datapath=datapath,
				buffer_id=msg.buffer_id, in_port=msg.in_port,
				actions=actions, data=data)
		datapath.send_msg(out_packet)
		
	else:
		neighbors_of_dpid = self.get_neighbors(dpid, self.ST)
		actions = []
		for out_port in neighbors_of_dpid:
			actions.append(parser.OFPActionOutput(out_port))
		
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out_packet = parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, 
			in_port=msg.in_port, actions=actions, data=data)
		datapath.send_msg(out_packet)

