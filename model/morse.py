import numpy as np
import networkx as nx
import torch
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
# from policy.initTagsAT import initObjectTags, initSubjectTags
from policy.propTags import propTags
# from policy.alarms import check_alarm, check_alarm_pre, printTime
from model.loss_1 import check_alarm, check_alarm_pre, printTime
from parse.eventType import UNUSED_SET, EXIT_SET, UPDATE_SET, cdm_events


class Morse:

    def __init__(self, device, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0, alarm_file = './results/alarms.txt'):
        self.device = device
        self.batch_size = batch_size
        self.sequence_size = sequence_size
        self.data_loader = data_loader

        self.format = format

        # initializer
        self.subj_init = None
        self.obj_inits = None

        # decay and attenuation
        self.a_b = 0.1
        self.a_e = 0.05

        # init graph
        self.G = nx.DiGraph()
        self.Nodes = {}
        self.Initialized_Nodes = {}
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

        self.cur_len = 0
        self.cur_batch = []
        self.cur_simple_net_grad_list = []
        self.cur_morse_grad_list = []
        self.cur_event_type_list = []
        self.cur_event_list = []

        self.remain_batch = []
        self.remain_event_type_list = []
        self.remain_event_list = []
        self.remain_simple_net_grad_list = []
        self.remain_morse_grad_list = []

        self.simple_net_grad_tensor = None
        self.morse_grad_tensor = None

    def forward(self):
        pass

    def backward(self):
        pass


    def propagate(self, event, s, o):
        propTags(event, s, o, format=self.format, morse = self)

    def add_event_generate_loss(self, event, gt):
        s_loss = None
        o_loss = None
        s_grad = None
        o_grad = None
        s_init_id = None
        o_init_id = None
        if event['src'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['src']] = True
        if event['dest'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['dest']] = True
        if cdm_events[event['type']] in UNUSED_SET:
            return None, None, None, None, None, None, None, None, None
        if cdm_events[event['type']] in UPDATE_SET:
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            self.propagate(event, src, dest)
            return None, None, None, None, None, None, None, None, None
        if cdm_events[event['type']] in EXIT_SET:
            try:
                self.processes[self.Nodes[event['src']].pid]['alive'] = False
                del self.Nodes[event['src']]
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None, None, None, None, None, None
        if event['src'] != -1 and event['dest'] != -1:
            self.G.add_edge(event['src'], event['dest'])
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            if src and dest:
                if (src.get_pid(), dest.get_name()) not in self.alarm:
                    self.alarm[(src.get_pid(), dest.get_name())] = False
                alarmArg = self.detect_alarm_pre(event, src, dest, gt, self.alarm_file)
                s_grad_pre = src.get_grad()
                s_initid_pre = src.getInitID()
                o_grad_pre = dest.get_grad()
                o_initid_pre = dest.getInitID()
                self.propagate(event, src, dest)
                diagnosis, s_loss, o_loss, s_tags, o_tags, grad_before_prop = self.detect_alarm(event, src, dest, alarmArg, gt, self.alarm_file)
                if grad_before_prop:
                    s_grad = s_grad_pre
                    s_init_id = s_initid_pre
                    o_grad = o_grad_pre
                    o_init_id = o_initid_pre
                else:
                    s_grad = src.get_grad()
                    s_init_id = src.getInitID()
                    o_grad = dest.get_grad()
                    o_init_id = dest.getInitID()

                if diagnosis is None:
                    if gt is not None:
                        fn = 0
                    else:
                        tn = 0
                else:
                    if gt is None:
                        fp = 0
                        if dest.id == '49463062-60DC-4F2A-39DD-1020749C0642':
                            stop = 0
                    else:
                        tp = 0

                return diagnosis, s_loss, o_loss, s_tags, o_tags, s_grad, o_grad, s_init_id, o_init_id
        
        return None, None, None, None, None, None, None, None, None

    def add_event(self, event, gt=None):
        if event['src'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['src']] = True
        if event['dest'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['dest']] = True
        if cdm_events[event['type']] in UNUSED_SET:
            return
        if cdm_events[event['type']] in UPDATE_SET:
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            self.propagate(event, src, dest)
            return
        if cdm_events[event['type']] in EXIT_SET:
            try:
                self.processes[self.Nodes[event['src']].pid]['alive'] = False
                del self.Nodes[event['src']]
            except KeyError:
                # print('Oops! Cannot find Node!')
                return
        if event['src'] != -1 and event['dest'] != -1:
            # self.G.add_edge(event['src'], event['dest'])
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            if src and dest:
                if (src.get_pid(), dest.get_name()) not in self.alarm:
                    self.alarm[(src.get_pid(), dest.get_name())] = False
                alarmArg = self.detect_alarm_pre(event, src, dest, gt, self.alarm_file)
                self.propagate(event, src, dest)
                diagnosis, s_loss, o_loss, s_tags, o_tags, grad_before_prop = self.detect_alarm(event, src, dest, alarmArg, gt, self.alarm_file)

                return diagnosis
        
        return

    def add_object(self, object):
        # self.G.add_node(object.id)
        # initObjectTags(object, self.obj_inits, format=self.format)
        # object.setObjTags(self.node_inital_tags[object.id].tolist())
        self.Nodes[object.id] = object
        self.Initialized_Nodes[object.id] = False
        if self.Nodes[object.id].type in {"MemoryObject", "UnnamedPipeObject"}:
            obj_tag = [1.0, 1.0]
        elif self.Nodes[object.id].type in {"SrcSinkObject"}:
            obj_tag = [0.0, 1.0]
        else:
            obj_tag = self.node_inital_tags[object.id]
        self.Nodes[object.id].setObjTags(obj_tag)

    def add_subject(self, subject):
        # self.G.add_node(subject.id)
        self.Nodes[subject.id] = subject
        self.Initialized_Nodes[subject.id] = False
        if subject.ppid and subject.ppid in self.Nodes:
            sub_tag = self.Nodes[subject.ppid].tags()
        else:
            sub_tag = [1.0, 1.0, 1.0, 1.0]
        self.Nodes[subject.id].setSubjTags(sub_tag)
        self.processes[subject.pid] = {}
        self.processes[subject.pid]['node'] = subject.id
        self.processes[subject.pid]['alive'] = True

    def detect_alarm(self,event,s ,o, alarmArg, gt, alarm_file = None):
        return check_alarm(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, gt, self.format, self, alarm_file)

    def detect_alarm_pre(self,event,s ,o, gt, alarm_file = None):
        return check_alarm_pre(event, s, o, self.alarm, self.created, self.alarm_sum, gt, self.format, self, alarm_file)
    
    def reset_tags(self):
        for nid in self.Nodes.keys():
            if self.Initialized_Nodes[nid] == False:
                if isinstance(self.Nodes[nid],Subject):
                    # sub_tag = self.node_inital_tags[nid].tolist()
                    sub_tag = [1.0, 1.0, 1.0, 1.0]
                    self.Nodes[nid].setSubjTags(sub_tag)
                else:
                    if self.Nodes[nid].type in {"SrcSinkObject","MemoryObject","UnnamedPipeObject"}:
                        obj_tag = [1.0, 1.0]
                    else:
                        obj_tag = self.node_inital_tags[nid].tolist()
                    self.Nodes[nid].setObjTags(obj_tag)

    def reset_morse(self):
        for nid in self.Initialized_Nodes.keys():
            self.Initialized_Nodes[nid] = False
        self.alarm = {}
