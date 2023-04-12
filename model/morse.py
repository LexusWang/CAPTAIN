import numpy as np
import networkx as nx
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.initTags import match_path, match_network_addr
from policy.propTags import propTags
from policy.alarms import check_alarm, check_alarm_pre
from model.loss import check_alarm_loss, check_alarm_pre_loss
from model.target_label import get_target_pre, get_target
from parse.eventParsing import parse_event_trace, parse_event_cadets
from parse.nodeParsing import parse_object as parse_object_
from parse.nodeParsing import parse_subject as parse_subject_


class Morse:
    def __init__(self, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0, alarm_file = './results/alarms.txt'):
        self.device = None
        self.batch_size = batch_size
        self.sequence_size = sequence_size
        self.data_loader = data_loader
        self.node_inital_tags = {}
        self.network_ini_tags = {}
        self.format = format


        # initializer
        self.subj_init = None
        self.obj_inits = None

        #
        self.tuneNetworkTags = False
        self.tuneFileTags = False

        # decay and attenuation
        self.a_b = 0.1
        self.a_e = 0.05

        # init graph
        self.G = nx.DiGraph()
        self.Nodes = {}
        self.srcsink_Nodes = {}
        self.Principals = {}
        self.processes = {}
        # self.Objects = {}

        # alarm
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]

        # alarm file
        self.alarm_file = alarm_file

        self.pos = 0

        self.node_set = set()
        self.edge_set = set()

        self.node_inital_tags = {}
        self.subject_tags = {}

        self.simple_net_grad_tensor = None
        self.morse_grad_tensor = None

    
    # def parse_event(self, datum, format='cadets', cdm_version = 18):
    #     return parse_event_(self, datum, format, cdm_version)
    def parse_event(self, datum, format, cdm_version):
        if format == 'trace':
            return parse_event_trace(self, datum, cdm_version)
        elif format == 'cadets':
            return parse_event_cadets(self, datum, cdm_version)

    def parse_object(self, datum, object_type, format, cdm_version):
        return parse_object_(self, datum, object_type, format, cdm_version)

    def parse_subject(self, datum, format, cdm_version):
        return parse_subject_(self, datum, format, cdm_version)
    
    def forward(self):
        pass

    def backward(self):
        pass


    def propagate(self, event, s, o):
        propTags(event, s, o, morse = self)

    def add_event_generate_loss(self, event, gt):
        diagnosis = None
        s_loss = None
        o_loss = None
        s_grad = None
        o_grad = None
        s_init_id = None
        o_init_id = None
        s_tags = None
        o_tags = None

        s_labels = []
        o_labels = []
        if event.type in {'update'}:
            src = self.Nodes.get(event.dest, None)
            dest = self.Nodes.get(event.dest2, None)
            self.propagate(event, src, dest)
            return None, None, None
        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)

        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            alarmArg = self.detect_alarm_pre(event, src, dest, gt, self.alarm_file)
            s_target, o_target = get_target_pre(event, src, dest, gt)
            
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

            if event.type in {'rename'}:
                dest2 = self.Nodes.get(event.dest2, None)
                self.propagate(event, dest, dest2)
            else:
                self.propagate(event, src, dest)

            diagnosis = self.detect_alarm(event, src, dest, alarmArg, gt, self.alarm_file)
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
                        

        return diagnosis, s_labels, o_labels
        
    def add_event(self, event, gt = None):
        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            alarmArg = self.detect_alarm_pre(event, src, dest, gt, self.alarm_file)
            if event.type in {'rename', 'update'}:
                dest2 = self.Nodes.get(event.dest2, None)
                self.propagate(event, dest, dest2)
            else:
                self.propagate(event, src, dest)
            diagnosis = self.detect_alarm(event, src, dest, alarmArg, gt, self.alarm_file)
            return diagnosis

    def add_object(self, object):
        # self.G.add_node(object.id)
        self.Nodes[object.id] = object
    
    def set_object_tags(self, object_id):
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
        

    def detect_alarm_loss(self,event,s ,o, alarmArg, gt, alarm_file = None):
        return check_alarm_loss(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, gt, self.format, self, alarm_file)

    def detect_alarm_pre_loss(self,event,s ,o, gt, alarm_file = None):
        return check_alarm_pre_loss(event, s, o, self.alarm, self.created, self.alarm_sum, gt, self.format, self, alarm_file)

    def detect_alarm(self,event,s ,o, alarmArg, gt, alarm_file = None):
        return check_alarm(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, gt, self.format, self, alarm_file)

    def detect_alarm_pre(self,event,s ,o, gt, alarm_file = None):
        return check_alarm_pre(event, s, o, self.alarm, self.created, self.alarm_sum, gt, self.format, self, alarm_file)

    def set_subject_tags(self, nid):
        if nid in self.node_inital_tags:
            sub_tag = [1.0, 1.0]
            sub_tag.extend(self.node_inital_tags[nid].tolist())
        else:
            sub_tag = [1.0, 1.0, 1.0, 1.0]
        self.Nodes[nid].setSubjTags(sub_tag)

    def reset_tags(self):
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            # if self.Initialized_Nodes[nid] == False:
            if isinstance(self.Nodes[nid], Subject):
                self.set_subject_tags(nid)
            else:
                self.set_object_tags(nid)
        
    def reset_morse(self):
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            # self.Initialized_Nodes[nid] = False
            self.Nodes[nid].updateTime = 0
        self.alarm = {}
