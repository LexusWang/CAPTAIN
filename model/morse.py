import pdb
import networkx as nx
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.initTags import match_path, match_network_addr
from policy.propTags import propTags
from policy.alarms import check_alarm
from model.target_label import get_target
from parse.eventParsing import parse_event_trace, parse_event_cadets, parse_event_linux
from parse.nodeParsing import parse_object as parse_object_
from parse.nodeParsing import parse_subject as parse_subject_


class Morse:
    def __init__(self, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0, alarm_file = './results/alarms.txt'):
        self.device = None
        self.batch_size = batch_size
        self.sequence_size = sequence_size
        self.data_loader = data_loader
        self.format = format

        # debug
        self.secret_src = 0
        self.secret_dest = 0
        self.secret_dest2 = 0

        #
        self.tuneNetworkTags = False
        self.tuneFileTags = False

        # init graph
        self.G = nx.DiGraph()
        self.Nodes = {}
        self.Principals = {}
        self.processes = {}

        # alarm
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]
        self.alarm_file = alarm_file

        self.white_name_set = set()

    def parse_event(self, datum, format, cdm_version):
        if format == 'trace':
            return parse_event_trace(self, datum, cdm_version)
        elif format == 'cadets':
            return parse_event_cadets(self, datum, cdm_version)
        elif format == 'linux':
            return parse_event_linux(self, datum)

    def parse_object(self, datum, object_type, format, cdm_version):
        return parse_object_(self, datum, object_type, format, cdm_version)

    def parse_subject(self, datum, format, cdm_version):
        return parse_subject_(self, datum, format, cdm_version)
    
    def forward(self):
        pass

    def backward(self):
        pass

    def propagate(self, event, s, o1, o2):
        return propTags(event, s, o1, o2)

    def add_event_generate_loss(self, event, gt):
        diagnosis = None
        s_labels = []
        o_labels = []
        kill_chains = []

        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None
        elif event.type == 'create':
            try:
                self.created[(self.Nodes[event.src].get_pid(), self.Nodes[event.dest].get_name())] = True
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        dest2 = self.Nodes.get(event.dest2, None)

        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            diagnosis = check_alarm(event, src, dest, self.alarm, self.created, self.alarm_file)
            s_target, o_target = get_target(event, src, dest, gt)
            
            if s_target:
                init_ids = src.getInitID()
                grads = src.get_grad()
                for i, item in enumerate(s_target):
                    if item:
                        if grads[i] > 0:
                            s_labels.append([init_ids[i], item])
                        elif grads[i] == 0:
                            pass
                        else:
                            s_labels.append([init_ids[i], 1-item])

                        if i == 2 and len(src.propagation_chain['i'])>0:
                            kill_chains.append(src.propagation_chain['i'])
                        elif i == 3 and len(src.propagation_chain['c'])>0:
                            kill_chains.append(src.propagation_chain['c'])

            if o_target:
                init_ids = dest.getInitID()
                grads = dest.get_grad()
                for i, item in enumerate(o_target):
                    if item:
                        if grads[i] > 0:
                            o_labels.append([init_ids[i], item])
                        elif grads[i] == 0:
                            pass
                        else:
                            o_labels.append([init_ids[i], 1-item])
                        
                        if i == 2 and len(dest.propagation_chain['i'])>0:
                            kill_chains.append(dest.propagation_chain['i'])
                        elif i == 3 and len(dest.propagation_chain['c'])>0:
                            kill_chains.append(dest.propagation_chain['c'])
            
            self.propagate(event, src, dest, dest2)

        return diagnosis, s_labels, o_labels, kill_chains
        
    def add_event(self, event, gt = None):
        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None
        elif event.type == 'create':
            try:
                self.created[(self.Nodes[event.src].get_pid(), self.Nodes[event.dest].get_name())] = True
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        dest2 = self.Nodes.get(event.dest2, None)

        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            diagnosis = check_alarm(event, src, dest, self.alarm, self.created, self.alarm_file)
            self.propagate(event, src, dest, dest2)
            return diagnosis

    def add_object(self, object):
        # self.G.add_node(object.id)
        self.Nodes[object.id] = object
    
    def set_object_tags(self, object_id):
        if self.Nodes[object_id].get_name() in self.white_name_set:
            obj_tag = [1.0, 1.0]
        else:
            if self.Nodes[object_id].type in {"MemoryObject", "UnnamedPipeObject"}:
                obj_tag = [1.0, 1.0]
            elif self.Nodes[object_id].type == "SrcSinkObject":
                obj_tag = [1.0, 1.0]
                if self.Nodes[object_id].name and self.Nodes[object_id].name.startswith('UnknownObject'):
                    if self.Nodes[object_id].name not in self.srcsink_Nodes:
                        self.srcsink_Nodes[self.Nodes[object_id].name] = []
                    else:
                        obj_tag = self.Nodes[self.srcsink_Nodes[self.Nodes[object_id].name][-1]].tags()
                    self.srcsink_Nodes[self.Nodes[object_id].name].append(object_id)
            elif self.Nodes[object_id].type == "NetFlowObject":
                if self.tuneNetworkTags:
                    obj_tag = self.network_ini_tags["{}:{}".format(self.Nodes[object_id].IP, int(self.Nodes[object_id].port))]
                else:
                    obj_tag = list(match_network_addr(self.Nodes[object_id].IP, self.Nodes[object_id].port))
            elif self.Nodes[object_id].type == "FileObject":
                if self.tuneFileTags:
                    obj_tag = self.node_inital_tags[object_id]
                else:
                    obj_tag = list(match_path(self.Nodes[object_id].path))
            else:
                obj_tag = [1.0, 1.0]
        self.Nodes[object_id].setObjTags(obj_tag)

    def add_subject(self, subject):
        # self.G.add_node(subject.id)
        self.Nodes[subject.id] = subject
        if subject.pid not in self.processes:
            self.processes[subject.pid] = {}
            self.processes[subject.pid]['nid'] = subject.id
            self.processes[subject.pid]['alive'] = True
            if subject.ppid and subject.ppid in self.processes and self.processes[subject.ppid]['alive']:
                parent_nid = self.processes[subject.ppid]['nid']
                self.Nodes[subject.id].setSubjTags(self.Nodes[parent_nid].tags())
                self.Nodes[subject.id].set_grad(self.Nodes[parent_nid].get_grad())
                self.Nodes[subject.id].setInitID(self.Nodes[parent_nid].getInitID())
            else:
                self.Nodes[subject.id].setSubjTags([1.0, 1.0, 1.0, 1.0])
        elif self.processes[subject.pid]['alive'] == False:
            self.processes[subject.pid]['nid'] = subject.id
            self.processes[subject.pid]['alive'] = True
            if subject.ppid and subject.ppid in self.processes and self.processes[subject.ppid]['alive']:
                parent_nid = self.processes[subject.ppid]['nid']
                self.Nodes[subject.id].setSubjTags(self.Nodes[parent_nid].tags())
                self.Nodes[subject.id].set_grad(self.Nodes[parent_nid].get_grad())
                self.Nodes[subject.id].setInitID(self.Nodes[parent_nid].getInitID())
            else:
                self.Nodes[subject.id].setSubjTags([1.0, 1.0, 1.0, 1.0])
        else:
            old_version_process_nid = self.processes[subject.pid]['nid']
            self.Nodes[subject.id].setSubjTags(self.Nodes[old_version_process_nid].tags())
            self.Nodes[subject.id].set_grad(self.Nodes[old_version_process_nid].get_grad())
            self.Nodes[subject.id].setInitID(self.Nodes[old_version_process_nid].getInitID())
            self.processes[subject.pid]['nid'] = subject.id
        
    def set_subject_tags(self, nid):
        self.Nodes[nid].setSubjTags([1.0, 1.0, 1.0, 1.0])

    def reset_tags(self):
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            if isinstance(self.Nodes[nid], Subject):
                self.set_subject_tags(nid)
            else:
                self.set_object_tags(nid)
        
    def reset_morse(self):
        # nid_list = list(self.Nodes.keys())
        # for nid in nid_list:
        #     self.Nodes[nid].updateTime = 0
        self.G = nx.DiGraph()
        self.Nodes = {}
        self.processes = {}
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]
