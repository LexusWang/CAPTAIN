import numpy as np
import networkx as nx
import torch
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
# from policy.initTagsAT import initObjectTags, initSubjectTags
from policy.propTags import propTags
from policy.alarms import check_alarm, check_alarm_pre, printTime


class Morse:

    def __init__(self, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0, alarm_file = './results/alarms.txt'):
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

    # -------------- tag getters ------------------ #

    def get_benign_thresh(self) -> float:
        return self.benign

    def get_susp_thresh(self) -> float:
        return self.suspect_env

    def get_stag_benign(self) -> float:
        return self.stag_benign

    def get_itag_benign(self) -> float:
        return self.itag_benign

    def get_ctag_benign(self) -> float:
        return self.ctag_benign

    def get_stag_susp_env(self) -> float:
        return self.stag_suspect_env

    def get_itag_susp_env(self) -> float:
        return self.itag_suspect_env

    def get_ctag_susp_env(self) -> float:
        return self.ctag_suspect_env

    def get_stag_dangerous(self) -> float:
        return self.stag_dangerous

    def get_itag_dangerous(self) -> float:
        return self.itag_dangerous

    def get_ctag_dangerous(self) -> float:
        return self.ctag_dangerous

    def get_attenuate_susp_env(self) -> float:
        return self.a_e

    def get_attenuate_benign(self) -> float:
        return self.a_b

    # ------------------ tag setters -------------- #

    def set_stag_benign(self, val):
        self.stag_benign = val

    def set_itag_benign(self, val):
        self.itag_benign = val

    def set_ctag_benign(self, val):
        self.ctag_benign = val

    def set_stag_susp_env(self, val):
        self.stag_suspect_env = val

    def set_itag_susp_env(self, val):
        self.itag_suspect_env = val

    def set_ctag_susp_env(self, val):
        self.ctag_suspect_env = val

    def set_stag_dangerous(self, val):
        self.stag_dangerous = val

    def set_itag_dangerous(self, val):
        self.itag_dangerous = val

    def set_itag_dangerous(self, val):
        self.itag_dangerous = val

    # ------------------ model getters-------------- #

    def get_benign_possibility(self, stag: float):
        return self.benign_thresh_model(stag)

    def get_susp_possibility(self, stag: float):
        return self.suspect_env_model(stag)

    def get_benign_thresh_grad(self)-> np.ndarray((1,2)):
        return self.benign_thresh_model.backward()

    def get_susp_thresh_grad(self) -> np.ndarray((1,2)):
        return self.suspect_env_model.backward()

    def benign_thresh_backward(self, grad: float):
        self.benign_thresh_model.backward(grad)

    def susp_thresh_backward(self, grad: float):
        self.suspect_env_model.backward(grad)

    # ------------------ weights setters ----------- #

    def a_b_setter(self, final_a_b_grad):
        self.a_b = self.a_b + final_a_b_grad

    def a_e_setter(self, final_a_e_grad):
        self.a_e = self.a_e + final_a_e_grad

    def benign_thresh_model_setter(self, w_grad, b_grad):
        self.benign_thresh_model.update_weight(w_grad, b_grad)

    def suspect_env_model_setter(self, w_grad, b_grad):
        self.suspect_env_model.update_weight(w_grad, b_grad)


    # ------------------ save & load ----------- #
    def save(path):
        pass

    def load(path):
        pass

    def propagate(self, event, s, o):
        propTags(event, s, o, format=self.format, morse = self)

    def add_event(self, event):
        # alarm_file = open(self.alarm_file,'a')
        alarm_file = self.alarm_file
        if event['type'] == 'EVENT_EXIT':
            try:
                self.processes[self.Nodes[event['src']].pid]['alive'] = False
            except KeyError:
                print('Oops! Cannot find Node!')
        if event['src'] != -1 and event['dest'] != -1:
            self.G.add_edge(event['src'], event['dest'])
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            if src and dest:
                if isinstance(src,Subject) and isinstance(dest,Subject):
                    if src.pid == dest.pid:
                        if src.id != dest.id:
                            print(event)
                if (src.get_pid(), dest.get_name()) not in self.alarm:
                    self.alarm[(src.get_pid(), dest.get_name())] = False
                alarmArg = self.detect_alarm_pre(event, src, dest, alarm_file)
                self.propagate(event, src, dest)
                return self.detect_alarm(event, src, dest, alarmArg, alarm_file)

    def add_object(self, object):
        self.G.add_node(object.id)
        # initObjectTags(object, self.obj_inits, format=self.format)
        # object.setObjTags(self.node_inital_tags[object.id].tolist())
        self.Nodes[object.id] = object

    def add_subject(self, subject):
        self.G.add_node(subject.id)
        if subject.pid in self.processes and self.processes[subject.pid]['alive']:
            subject.setSubjTags(self.Nodes[self.processes[subject.pid]['node']].tags())
        # else:
        #     # initSubjectTags(subject, self.subj_init)
        #     subject.setSubjTags(self.node_inital_tags[subject.id].tolist())
        # subject.setSubjTags(self.node_inital_tags[subject.id].tolist())
        self.processes[subject.pid] = {}
        self.processes[subject.pid]['node'] = subject.id
        self.processes[subject.pid]['alive'] = True
        self.Nodes[subject.id] = subject

    def detect_alarm(self,event,s ,o, alarmArg, alarm_file = None):
        return check_alarm(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, self.format, self, alarm_file)

    def detect_alarm_pre(self,event,s ,o, alarm_file = None):
        return check_alarm_pre(event, s, o, self.alarm, self.created, self.alarm_sum, self.format, self, alarm_file)
    
    def reset_tags(self):
        for nid in self.Nodes.keys():
            if isinstance(self.Nodes[nid],Subject):
                self.Nodes[nid].setSubjTags(self.node_inital_tags[nid].tolist())
            else:
                self.Nodes[nid].setObjTags(self.node_inital_tags[nid].tolist())

    def reset_alarms(self):
        self.alarm = {}
