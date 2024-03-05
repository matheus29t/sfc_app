import sqlite3
import json
import logging
import time
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
from webob import Response
from asymlist import Node, AsymLList

conn = sqlite3.connect('nfv.sqlite')
cur = conn.cursor()
flows = {}
DELTA = 3000
##################
class vnf(Node):
    def __init__(self, vnf_id, is_bidirect=True, cur=None):
        super().__init__(vnf_id, is_bidirect)
        ### added iftype bitwise support: 1(01)-out, 2(10)-in, 3(11)-inout
        ### & 1 - first bit; & 2 - second bit
        ### Ex. bitwise iftype selection:
        ###  'select * from vnf where  iftype & 2 != 0'
        ###  'select dpid, in_port, locator_addr from vnf where id=X and iftype & 1 != 0'
        cur.execute(''' select dpid, in_port, locator_addr, bidirectional from vnf where id=? and iftype & 2 != 0''', (self.id,)) 
        self.dpid_in, self.port_in, self.locator_addr_in, is_bidirect = cur.fetchone()
        logging.debug('Locator addr: %s', self.locator_addr_in)
        cur.execute(''' select dpid, in_port, locator_addr from vnf where id=? and iftype & 1 != 0''', (self.id,))
        self.dpid_out, self.port_out, self.locator_addr_out = cur.fetchone()
        if is_bidirect.lower() == "false":
            self.is_bidirect = False

class Group:
    def __init__(self, group_id):
        self.group_id = group_id
        self.vnfs = []  # List to store VNFs in this group
        self.last_used_index = -1  # Track the last used VNF's index for round-robin

    def add_vnf(self, vnf_id):
        if vnf_id not in self.vnfs:
            self.vnfs.append(vnf_id)
        
    def remove_vnf(self, vnf_id):
        if vnf_id in self.vnfs:
            index = self.vnfs.index(vnf_id)
            self.vnfs.remove(vnf_id)
            if index <= self.last_used_index:
                self.last_used_index -= 1

    def get_next_vnf(self):
        if not self.vnfs:
            return None
        self.last_used_index = (self.last_used_index + 1) % len(self.vnfs)
        self.update_database()
        return self.vnfs[self.last_used_index]

    def update_last_used_vnf_index(self):
        # Connect to the database
        conn = sqlite3.connect('nfv.sqlite')
        cur = conn.cursor()
        # Fetch the last used VNF for the group
        cur.execute('''SELECT last_used_vnf FROM group_info WHERE group_id = ?''', (self.group_id,))
        last_used_vnf_id = cur.fetchone()[0]
        if last_used_vnf_id is not None:
            # Find the index of the last used VNF in the self.vnfs list
            if last_used_vnf_id in self.vnfs:
                self.last_used_index = self.vnfs.index(last_used_vnf_id)
        cur.close()
        conn.close()

    def update_database(self):
        # Connect to the database
        conn = sqlite3.connect('nfv.sqlite')
        cur = conn.cursor()
        cur.execute('''UPDATE group_info SET last_used_vnf = ? WHERE group_id = ?''', (self.vnfs[self.last_used_index], self.group_id))
        cur.connection.commit()
        logging.debug('Updated last used vnf for group %s in the DB: %s', self.group_id, self.vnfs[self.last_used_index])
        cur.close()
        conn.close()

    def __str__(self):
        return f"Group ID: {self.group_id}, VNFs: {self.vnfs}, Last Used Index: {self.last_used_index}"



class sfc(AsymLList):
    def __init__(self, flow_id, nodeClass=vnf, cur=None):
        self.cur = cur
        self.cur.execute('''select * from flows where id = ? ''', (flow_id,))
        self.flow_spec = cur.fetchone()
        if self.flow_spec is None:
            logging.debug('Flow %s is not defined', flow_id)
            raise ValueError("Flow is not known")
        self.flow_dict = {}
        self.flows = {}
        (self.flow_id, self.name, self.flow_dict['in_port'], 
         self.flow_dict['eth_dst'], self.flow_dict['eth_src'], self.flow_dict['eth_type'],
         self.flow_dict['ip_proto'], self.flow_dict['ipv4_src'], self.flow_dict['ipv4_dst'],
         self.flow_dict['tcp_src'], self.flow_dict['tcp_dst'], self.flow_dict['udp_src'],
         self.flow_dict['udp_dst'], self.flow_dict['ipv6_src'], self.flow_dict['ipv6_dst'],
         self.service_id) = self.flow_spec
        if not self.flow_dict['eth_type']:
            self.flow_dict['eth_type'] = 0x0800

        self.flow_id = int(flow_id)
        self.reverse_flow_id = self.flow_id+DELTA
        self.flows[self.flow_id] = self.flow_dict
        self.flows[self.reverse_flow_id] = sfc_app_cls.reverse_flow(self.flows[self.flow_id])
        self.group_ids = self.get_ordered_group_ids()
        self.groups = self.fill_groups()
        group_id = self.group_ids.pop(0)
        vnf_id = self.groups[group_id].get_next_vnf()
        logging.debug('Selected vnf with id %s from group %s', vnf_id, group_id)
        super().__init__(vnf_id, is_bidirect=True, nodeClass=nodeClass, cur=self.cur)   
        self.fill()

    def __str__(self):
        return str(self.forward())
    
    def fill_group_from_db(self, group_id):
        group = Group(group_id)
        # Query for VNFs belonging to the group
        cur.execute('''SELECT vnf_id FROM group_vnfs WHERE group_id = ? ORDER BY vnf_order''', (group_id,))
        vnfs = cur.fetchall()
        for vnf in vnfs:
            group.add_vnf(vnf[0])
        group.update_last_used_vnf_index()  # Update the last used index based on database
        return group

    def fill_groups(self):
        groups = {}
        # Initialize Group objects
        for group_id in self.group_ids:
            group = self.fill_group_from_db(group_id)
            groups[group_id] = group
        return groups

    def get_ordered_group_ids(self):
        # Fetch all group IDs and next group IDs for the given service ID
        cur.execute("SELECT group_id, next_group_id FROM service WHERE service_id = ?", (self.service_id,))
        rows = cur.fetchall()

        # Create a mapping from group_id to next_group_id
        group_to_next = {row[0]: row[1] for row in rows if row[1] is not None}

        # Find the first group ID (the one that does not appear as a next_group_id)
        start_group_id = None
        for group_id in group_to_next:
            if not any(group_id == next_id for next_id in group_to_next.values()):
                start_group_id = group_id
                break

        # Follow the chain to get the ordered list of group IDs
        ordered_group_ids = []
        while start_group_id is not None:
            ordered_group_ids.append(start_group_id)
            start_group_id = group_to_next.get(start_group_id, None)

        return ordered_group_ids

    def append(self):
        if not self.group_ids:
            return None
        group_id = self.group_ids.pop(0)
        vnf_id = self.groups[group_id].get_next_vnf()
        logging.debug('Selected vnf with id %s from group %s', vnf_id, group_id)
        return super().append(vnf_id, cur=self.cur)

    def fill(self):
        logging.debug('Filling...')
        while self.append():
            pass
        return self.last        

    def install_catching_rule(self, sfc_app_cls):
        logging.debug("Adding catching rule...")    
        actions = []
        flow_id = self.flow_id
        for flow_id in (self.flow_id, self.reverse_flow_id):
            for dp in sfc_app_cls.datapaths.values():
                match = sfc_app_cls.create_match(dp.ofproto_parser, self.flows[flow_id])
                sfc_app_cls.add_flow(dp, 1, match, actions, metadata=flow_id, goto_id=2)
            if self.back is None:
                break
        return Response(status=200)

    def delete_rule(self, sfc_app_cls, flow_match):
        logging.debug('Deleting rule...')
        flow_dict = self.flows[flow_match]
        for dp in sfc_app_cls.datapaths.values():
            match_del = sfc_app_cls.create_match(dp.ofproto_parser, flow_dict)
            sfc_app_cls.del_flow(datapath=dp, match=match_del)

    def install_steering_rule(self, sfc_app_cls, dp_entry, in_port_entry, flow_match):
        logging.debug("Adding steering rule...")
        actions = []
        dp = dp_entry
        parser = dp.ofproto_parser
        flow_dict = self.flows[flow_match]
        flow_dict['in_port'] = in_port_entry
        match = sfc_app_cls.create_match(parser, flow_dict)
        if flow_match < DELTA:
            for vnf in self.forward():
                #dpid_out = vnf.dpid_out
                actions.append(parser.OFPActionSetField(eth_dst=vnf.locator_addr_in)) 
                sfc_app_cls.add_flow(dp, 8, match, actions, goto_id=1)
                actions = []
                flow_dict['in_port'] = vnf.port_out
                dp = sfc_app_cls.datapaths[vnf.dpid_out] 
                match = sfc_app_cls.create_match(parser, flow_dict)
        else:
            for vnf in self.backward(): 
                #dpid_out = vnf.dpid_out
                actions.append(parser.OFPActionSetField(eth_dst=vnf.locator_addr_out)) 
                sfc_app_cls.add_flow(dp, 8, match, actions, goto_id=1)
                actions = []
                flow_dict['in_port'] = vnf.port_out
                dp = sfc_app_cls.datapaths[vnf.dpid_out] 
                match = sfc_app_cls.create_match(parser, flow_dict)

#################################

class SFCController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SFCController, self).__init__(req, link, data, **config)
        self.sfc_api_app = data['sfc_api_app']

    @route('hello', '/{greeting}/{name}', methods=['GET'])
    def hello(self, req, **kwargs):
        greeting = kwargs['greeting']
        name = kwargs['name']
        message = greeting +' '+ name
        privet = {'message': message}
        body = json.dumps(privet)
        return Response(content_type='application/json', body=body.encode('utf-8'), status=200)

    @route('add-flow', '/add_flow/{flow_id}', methods=['GET'])
    def api_add_flow(self, req,  **kwargs):
        sfc_ap = self.sfc_api_app
        flow_id = kwargs['flow_id']
        logging.debug('FLOW ID: %s', flow_id)
        try:
            flows[flow_id] = sfc(flow_id, cur=cur)
        except ValueError:
            message = {'Result': 'Flow {} is not defined'.format(flow_id)}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status=404)
        except TypeError:
            message = {'Result': 'DB inconsistency'}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status=500)
        logging.debug('SFC: %s', str(flows[flow_id]))
        flows[flow_id].install_catching_rule(sfc_ap)

    @route('delete-flow', '/delete_flow/{flow_id}', methods=['GET'])
    def api_delete_flow(self, req,  **kwargs):
        '''Deletes flow from the application and clears the corresponding rule from DPs  '''
        sfc_ap = self.sfc_api_app
        flow_id = kwargs['flow_id']
        cur.execute('''select * from flows where id = ?''', (kwargs['flow_id'],))
        flow_spec = cur.fetchone()
        flow_dict = {}
        if not flow_spec: return Response(status=404)

        (flow_id, name, flow_dict['in_port'], flow_dict['eth_dst'],
         flow_dict['eth_src'], flow_dict['eth_type'], flow_dict['ip_proto'],
         flow_dict['ipv4_src'], flow_dict['ipv4_dst'], flow_dict['tcp_src'],
         flow_dict['tcp_dst'], flow_dict['udp_src'], flow_dict['udp_dst'],
         flow_dict['ipv6_src'], flow_dict['ipv6_dst'], service_id) = flow_spec
        if not flow_dict['eth_type']: flow_dict['eth_type'] = 0x0800 
        reverse_flow_dict = sfc_app_cls.reverse_flow(flow_dict) 
        for flow_dict in (flow_dict, reverse_flow_dict):

            for dp in sfc_ap.datapaths.values():
                match_del = sfc_ap.create_match(dp.ofproto_parser, flow_dict)
                sfc_ap.del_flow(datapath=dp, match=match_del)
        try:    
            del flows[str(flow_id)]
            logging.debug('Flow %s deleted', flow_id)
        except KeyError:
            logging.debug('Flow %s not found, but an attempt to delete it from DPs has been performed', flow_id)
        return Response(status=200)

    @route('flows', '/flows/{flow_id}', methods=['GET'])
    def api_show_flow(self, req, **kwargs):
        flow_id = kwargs['flow_id']
        try:
            body = json.dumps({flow_id:str(flows[flow_id])})
            return Response(content_type='application/json', body=body.encode('utf-8'), status=200)
        except KeyError:
            body = json.dumps({'ERROR':'Flow {} not found/not installed'.format(flow_id)})
            return Response(content_type='application/json', body=body.encode('utf-8'), status=404)

    @route('flows_all', '/flows', methods=['GET'])
    def api_show_flows(self, req):
        logging.debug('FLOWS: {}'.format(str(flows)))
        body = json.dumps(str(flows))
        return Response(content_type='application/json', body=body.encode('utf-8'), status=200)

class sfc_app_cls(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(sfc_app_cls, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SFCController, {'sfc_api_app': self})
        self.datapaths = {}
        self.vnf_last_seen = {}
        hub.spawn(self.monitor_heartbeats)

######## database definition
#        conn = sqlite3.connect('nfv.sqlite')
#        cur = conn.cursor()
#        cur.executescript('''

#        DROP TABLE IF EXISTS vnf; 

#        CREATE TABLE vnf (
#            id  INTEGER NOT NULL,
#            name    TEXT,
#            type_id  INTEGER,
#            group_id    INTEGER,
#            geo_location    TEXT,
#            iftype  INTEGER,
#            bidirectional   BOOLEAN,
#            dpid    INTEGER,
#            in_port INTEGER,
#            locator_addr  NUMERIC
#            PRIMARY KEY(id,iftype)
#        );
#        create unique index equipment_uind on vnf (name,iftype)

#        ''')
#        conn.commit()
#        cur.close()
########  END of database definition

######### Register/Unregister DataPathes in datapth dictionary
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


########## Setting default rules upon DP is connectted
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

#### Set flow to retrieve registration packet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=30012)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)
#### Set flow to retrieve heartbeat packet
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=30013)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)
#### Set defaults for table 1 and 2
        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath, 0, match, actions, goto_id=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=2)
################ Packet_IN handler ####################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto 
        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        self.logger.debug('OFPPacketIn received: '
                          'buffer_id=%x total_len=%d reason=%s '
                          'table_id=%d cookie=%d  match=%s ',
                          msg.buffer_id, msg.total_len, reason,
                          msg.table_id, msg.cookie, msg.match)
        try:
            flow_match = msg.match['metadata']
            if msg.match['metadata'] > DELTA:
                flow_id = flow_match - DELTA
            else:
                flow_id = flow_match
            in_port_entry = msg.match['in_port']
            dp_entry = datapath

####### Deleting catching rules
            logging.debug('Deleting catching rules - flow:%d match:%d ...', flow_id, flow_match)
            flows[str(flow_id)].delete_rule(self, flow_match)

####### Installing steering rules 
            logging.debug('Installing steering rules - flow:%d match:%d ...', flow_id, flow_match)
            flows[str(flow_id)].install_steering_rule(self, dp_entry, in_port_entry, flow_match)
            
        except KeyError:
            flow_match = None
            pass

####### VNF self registrtation & heartbeat
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        #pkt_arp = pkt.get_protocol(arp.arp) 
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        #pkt_ip = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            if pkt_udp.dst_port == 30012: # Registration port
                reg_string = pkt.protocols[-1]
                reg_info = json.loads(reg_string)
                name = reg_info['register']['name']
                vnf_id = reg_info['register']['vnf_id']
                logging.debug('VNF ID from reg packet %s', vnf_id)
                type_id = reg_info['register']['type_id']
                group_id = reg_info['register']['group_id']
                geo_location = reg_info['register']['geo_location']
                iftype = reg_info['register']['iftype']
                bidirectional = reg_info['register']['bidirectional']
                dpid = datapath.id
                locator_addr = pkt_eth.src
                logging.debug("Inserting self-registartion info into DB")
                cur.execute('''REPLACE INTO vnf (id, name, type_id,
                           group_id, geo_location, iftype, bidirectional,
                           dpid, in_port, locator_addr  ) VALUES ( ?, ?, ?,
                           ?, ?, ?, ?, ?, ?, ? )''', 
                            (vnf_id, name, type_id, group_id, geo_location,
                             iftype, bidirectional, dpid, in_port, locator_addr)
                           )
                # Update or insert into group_info table with the last used VNF
                cur.execute('SELECT group_id FROM group_info WHERE group_id = ?', (group_id,))
                if cur.fetchone() is None:
                    # Insert new group info if it doesn't exist
                    cur.execute('''INSERT INTO group_info (group_id, last_used_vnf)
                                VALUES (?, ?)''', (group_id, vnf_id))
                else:
                    # Update last used VNF for existing group
                    cur.execute('''UPDATE group_info SET last_used_vnf = ? WHERE group_id = ?''',
                                (vnf_id, group_id))

                # Insert VNF into group_vnfs table
                cur.execute('SELECT vnf_order FROM group_vnfs WHERE vnf_id = ?', (vnf_id,))
                if cur.fetchone() is None:
                    # Assuming vnf_order needs to be calculated or provided. Here we just fetch the max order and add one.
                    cur.execute('SELECT MAX(vnf_order) FROM group_vnfs WHERE group_id = ?', (group_id,))
                    max_order = cur.fetchone()[0]
                    vnf_order = max_order + 1 if max_order is not None else 0

                    cur.execute('''INSERT INTO group_vnfs (group_id, vnf_id, vnf_order)
                                VALUES (?, ?, ?)''', (group_id, vnf_id, vnf_order))

                cur.execute('SELECT id FROM vnf WHERE name = ? AND  iftype = ?',
                            (name, iftype)
                            )
                vnf_id = cur.fetchone()[0]

                conn.commit()
                #cur.close()
            if pkt_udp and pkt_udp.dst_port == 30013:  # Assuming 30013 is the heartbeat port
                # Parse the heartbeat packet
                heartbeat_payload = pkt.protocols[-1]
                try:
                    heartbeat_info = json.loads(heartbeat_payload)
                    vnf_id = heartbeat_info['vnf_id']  # Assuming the payload contains a 'vnf_id' key
                    # Update the last seen time for this VNF
                    if vnf_id not in self.vnf_last_seen:
                        logging.debug("VNF %s is alive!", vnf_id)
                    self.vnf_last_seen[vnf_id] = time.time()
                except ValueError as e:
                    self.logger.error('Failed to parse heartbeat packet: %s', str(e))
                
############# Function definitions #############
    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, table_id=0, metadata=None, goto_id=None):
        logging.debug("Add flow to DP %d", datapath.id) 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if goto_id:
            #inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] 

            if metadata:
                inst.append(parser.OFPInstructionWriteMetadata(metadata, 0xffffffff))
            inst.append(parser.OFPInstructionGotoTable(goto_id))
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            #inst.append(parser.OFPInstructionWriteMetadata(1,0xffffffff))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        ''' Deletes a flow defined by match from a DP '''
        logging.debug("Delele flow from DP %d", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    def create_match(self, parser, fields):
        '''Creates OFP match struct from the list of fields. New API.'''
        flow_dict = {}
        for k, v in fields.items():
            if  v is not None:
                flow_dict[k] = v
        match = parser.OFPMatch(**flow_dict)
        return match

    def reverse_flow(flow_dict):
        '''Creates reverse flow dict '''
        reverse_flow_dict = {**flow_dict}
        reverse_flow_dict['eth_src'] = flow_dict['eth_dst']
        reverse_flow_dict['eth_dst'] = flow_dict['eth_src']
        reverse_flow_dict['ipv4_src'] = flow_dict['ipv4_dst']
        reverse_flow_dict['ipv4_dst'] = flow_dict['ipv4_src']
        reverse_flow_dict['tcp_src'] = flow_dict['tcp_dst']
        reverse_flow_dict['tcp_dst'] = flow_dict['tcp_src']
        reverse_flow_dict['udp_src'] = flow_dict['udp_dst']
        reverse_flow_dict['udp_dst'] = flow_dict['udp_src']
        reverse_flow_dict['ipv6_src'] = flow_dict['ipv6_dst']
        reverse_flow_dict['ipv6_dst'] = flow_dict['ipv6_src']
        return reverse_flow_dict

######### Health Checks ###########
    def monitor_heartbeats(self):
        while True:
            current_time = time.time()
            for vnf_id, last_seen in list(self.vnf_last_seen.items()):
                if current_time - last_seen > 4:  # Consider VNF down if no heartbeat for 4 seconds
                    logging.debug('VNF %s is down!', vnf_id)
                    del self.vnf_last_seen[vnf_id]
                    self.regenerate_sfc_for_vnf(int(vnf_id))
            hub.sleep(10)

    def regenerate_sfc_for_vnf(self, vnf_id):
        """
        Regenerate the SFC for flows affected by the downed VNF.
        """
        affected_flows = []
        
        # Identify which flows are affected by the downed VNF
        logging.debug('FLOWS: %s', flows)
        for flow_id, sfc_instance in flows.items():
            if vnf_id in [vnf.id for vnf in sfc_instance.forward()]:
                logging.info(f"VNF {vnf_id} is down. Initiating flow regeneration.")
                affected_flows.append(flow_id)
        
        # For each affected flow, regenerate
        for flow_id in affected_flows:
            self.regenerate_sfc(flow_id)

    def regenerate_sfc(self, flow_id):
        """
        Regenerate the SFC for a given flow ID.
        """
        logging.debug(f"Regenerating SFC for flow ID: {flow_id}")
        try:
            flows[flow_id] = sfc(flow_id, cur=cur)
        except ValueError:
            message = {'Result': 'Flow {} is not defined'.format(flow_id)}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status=404)
        except TypeError:
            message = {'Result': 'DB inconsistency'}
            body = json.dumps(message)
            return Response(content_type='application/json', body=body.encode('utf-8'), status=500)
        logging.info('Flow %s has been regenerated.', flow_id)
        logging.debug('SFC: %s', str(flows[flow_id]))
        flows[flow_id].install_catching_rule(self) # Use 'self' to refer to the current instance of sfc_app_cls
