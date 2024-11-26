import pdb
import networkx as nx
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.initTags import match_path, match_network_addr
from policy.propTags import propTags, dump_event_feature
from policy.alarms import check_alarm
from model.target_label import get_target
from parse.cdm18.cadets_parser import parse_event_cadets
from parse.cdm18.trace_parser import parse_event_trace
from parse.cdm18.fivedirections_parser import parse_event_fivedirections
from parse.lttng_parser import parse_event_linux
from parse.nodeParsing import parse_object as parse_object_
from parse.nodeParsing import parse_subject as parse_subject_
from utils.utils import getTime

class CAPTAIN:
    def __init__(self, att, decay, alarm_file = './results/alarms.txt'):
        self.device = None
        self.att = att
        self.decay = decay
        self.mode = 'train'

        # self.tuneNetworkTags = True
        # self.tuneFileTags = True

        # init graph
        # self.G = nx.DiGraph()
        self.Nodes = {}
        self.Principals = {}
        self.processes = {}

        # alarm
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]
        self.alarm_file = alarm_file

        # customization
        # alpha 
        # self.white_name_set = set()
        self.alpha_dict = {}
        # lambda dictionary
        self.lambda_dict = {}
        # tau dictionary
        self.tau_dict = {}
        self.tau_modify_dict = {}

    # def parse_event(self, datum, format, cdm_version):
    #     if format == 'trace':
    #         return parse_event_trace(self, datum, cdm_version)
    #     elif format == 'cadets':
    #         return parse_event_cadets(self, datum, cdm_version)
    #     elif format == 'fivedirections':
    #         return parse_event_fivedirections(self, datum, cdm_version)
    #     elif format == 'linux':
    #         return parse_event_linux(self, datum)

    def parse_object(self, datum, object_type, format, cdm_version):
        return parse_object_(self, datum, object_type, format, cdm_version)

    def parse_subject(self, datum, format, cdm_version):
        return parse_subject_(self, datum, format, cdm_version)
    
    def forward(self):
        pass

    def backward(self):
        pass

    def adjust_tau(self, fp_counter):
        # Sort the event_key by the number of alarms it triggered and keep the top 50%
        sorted_items = sorted(fp_counter.items(), key=lambda x: sum(x[1]), reverse=True)
        half_length = len(sorted_items) // 2
        selected_items = sorted_items[:half_length]
        selected_dict = dict(selected_items)

        for event_key in self.tau_modify_dict.keys():
            if event_key not in selected_dict.keys():
                for i, v in enumerate(self.tau_modify_dict[event_key]):
                    self.tau_dict[event_key][i] += self.tau_modify_dict[event_key][i]
                    self.tau_modify_dict[event_key][i] *= 0.5


        for event_key in selected_dict.keys():
            for i, v in enumerate(selected_dict[event_key]):
                if v > 10:
                    if event_key not in self.tau_dict.keys():
                        self.tau_dict[event_key] = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
                        self.tau_modify_dict[event_key] = [0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25]
                    self.tau_dict[event_key][i] -= self.tau_modify_dict[event_key][i]
                    self.tau_modify_dict[event_key][i] *= 0.5
        
            
            
    def add_event_generate_loss(self, event, gt):
        diagnosis = None
        loss = 0
        s_labels = []
        o_labels = []
        kill_chains = []
        loss_lambda_grads = []

        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                return None, None, None, None
        elif event.type == 'create':
            try:
                self.created[(self.Nodes[event.src].get_pid(), self.Nodes[event.dest].get_name())] = True
            except KeyError:
                return None, None, None, None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        dest2 = self.Nodes.get(event.dest2, None)

        if src:
            event_feature_str = str(dump_event_feature(event, src, dest, dest2))
            if dest and (src.get_pid(), event.type, dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), event.type, dest.get_name())] = False
            tau = self.tau_dict.get(event_feature_str, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5])
            diagnosis, tag_indices = check_alarm(event, src, dest, self.alarm, self.created, self.alarm_file, tau)
            s_target, o_target = get_target(event, src, dest, gt)
            if dest and self.alarm[(src.get_pid(), event.type, dest.get_name())]:
                self.alarm[(src.get_pid(), event.type, dest.get_name())] = False

            loss_thr_grads = {}
            loss_thr_grads[event_feature_str] = [None, None, None, None, None, None, None, None]

            if s_target:
                lambda_grads = src.get_lambda_grad()
                grads = src.get_grad()
                for i, item in enumerate(s_target):
                    if item:

                        f = src.tags()[i] - tau[i]
                        if item == 0:
                            loss += (1+f)*(1+f)
                            gradients = (2*f+2)
                        else:
                            loss += (1-f)*(1-f)
                            gradients = (2*f-2)

                        for key in grads[i].keys():
                            s_labels.append((key, gradients*grads[i][key]))

                        for key in lambda_grads[i].keys():
                            loss_lambda_grads.append((key, gradients*lambda_grads[i][key]))

                        loss_thr_grads[event_feature_str][i] = gradients*(-1)

                        # for key in grads[i].keys():
                        #     s_labels.append((key, (2*item-1)*(-1.0)*grads[i][key]))

                        # for key in lambda_grads[i].keys():
                        #     loss_lambda_grads.append((key, (2*item-1)*(-1.0)*lambda_grads[i][key]))
                        
                        if i == 2 and len(src.propagation_chain['i'])>0:
                            kill_chains.append(src.propagation_chain['i'])
                        elif i == 3 and len(src.propagation_chain['c'])>0:
                            kill_chains.append(src.propagation_chain['c'])

            if o_target:
                lambda_grads = dest.get_lambda_grad()
                grads = dest.get_grad()
                for i, item in enumerate(o_target):
                    if item:

                        f = dest.tags()[i] - tau[i+4]
                        if item == 0:
                            loss += (1+f)*(1+f)
                            gradients = (2*f+2)
                        else:
                            loss += (1-f)*(1-f)
                            gradients = (2*f-2)

                        for key in grads[i].keys():
                            o_labels.append((key, gradients*grads[i][key]))

                        for key in lambda_grads[i].keys():
                            loss_lambda_grads.append((key, gradients*lambda_grads[i][key]))

                        loss_thr_grads[event_feature_str][i+4] = gradients*(-1)

                        # for key in grads[i].keys():
                        #     o_labels.append((key, (2*item-1)*(-1.0)*grads[i][key]))
                        
                        # for key in lambda_grads[i].keys():
                        #     loss_lambda_grads.append((key, (2*item-1)*(-1.0)*lambda_grads[i][key]))
                            
                        if i == 2 and len(dest.propagation_chain['i'])>0:
                            kill_chains.append(dest.propagation_chain['i'])
                        elif i == 3 and len(dest.propagation_chain['c'])>0:
                            kill_chains.append(dest.propagation_chain['c'])
            
            prop_lambda = self.lambda_dict.get(event_feature_str, 0)
            propTags(event, src, dest, dest2, att = self.att, decay = self.decay, prop_lambda=prop_lambda, tau=tau)

        return diagnosis, tag_indices, s_labels, o_labels, kill_chains, loss_lambda_grads, loss_thr_grads, loss
        
    def add_event(self, event, gt = None):                        
        diagnosis = None
        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        dest2 = self.Nodes.get(event.dest2, None)

        if src:
            event_feature_str = str(dump_event_feature(event, src, dest, dest2))

            try:
                if event.type == 'exit':
                    self.processes[src.pid]['alive'] = False
                    # del self.Nodes[event.src]
                elif event.type == 'create':
                    self.created[(src.get_pid(), dest.get_name())] = True
            except Exception:
                # print('Oops! Cannot find Node!')
                return None

            if dest and (src.get_pid(), event.type, dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), event.type, dest.get_name())] = False
            tau = self.tau_dict.get(event_feature_str, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5])
            prop_lambda = self.lambda_dict.get(event_feature_str, 0)
            diagnosis, tag_indices = check_alarm(event, src, dest, self.alarm, self.created, self.alarm_file, tau)
            try:
                propTags(event, src, dest, dest2, att = self.att, decay = self.decay, prop_lambda=prop_lambda, tau=tau, update_gradients=False)
            except AssertionError:
                ## the format of the event is incorrect
                return None

            # try:
            #     if event.type == 'update':
            #         del self.Nodes[event.dest]
            #     elif event.type == 'rename':
            #         del self.Nodes[event.dest]
            # except KeyError:
            #     # print('Oops! Cannot find Node!')
            #     return None
            
        return diagnosis

    def add_object(self, object):
        # self.G.add_node(object.id)
        self.Nodes[object.id] = object
    
    def set_object_tags(self, object_id):
        if (self.Nodes[object_id].type, self.Nodes[object_id].get_name()) in self.alpha_dict:
            obj_tag = [self.alpha_dict[(self.Nodes[object_id].type, self.Nodes[object_id].get_name())], 1.0]
        else:
            obj_tag = self.get_default_a(self.Nodes[object_id].type, self.Nodes[object_id].get_name())
        self.Nodes[object_id].setObjTags(obj_tag)

    def get_default_a(self, node_type, node_name):
        if node_type == "NetFlowObject":
            return list(match_network_addr(node_name))
        elif node_type == "FileObject":
            return list(match_path(node_name))
        else:
            return [1.0, 1.0]

    def add_subject(self, subject):
        # self.G.add_node(subject.id)
        self.Nodes[subject.id] = subject
        if subject.pid in self.processes and self.processes[subject.pid]['alive']:
            old_version_process_nid = self.processes[subject.pid]['nid']

            self.Nodes[subject.id].setSubjTags(self.Nodes[old_version_process_nid].tags())
            if self.mode == 'train':
                self.Nodes[subject.id].set_grad(self.Nodes[old_version_process_nid].get_grad())
                self.Nodes[subject.id].set_lambda_grad(self.Nodes[old_version_process_nid].get_lambda_grad())

            self.processes[subject.pid]['nid'] = subject.id
            # del self.Nodes[old_version_process_nid]

            return
        elif subject.pid not in self.processes:
            self.processes[subject.pid] = {}

        self.processes[subject.pid]['nid'] = subject.id
        self.processes[subject.pid]['alive'] = True
        if subject.ppid and subject.ppid in self.processes and self.processes[subject.ppid]['alive']:
            parent_nid = self.processes[subject.ppid]['nid']
            self.Nodes[subject.id].setSubjTags(self.Nodes[parent_nid].tags())
            if self.mode == 'train':
                self.Nodes[subject.id].set_grad(self.Nodes[parent_nid].get_grad())
                self.Nodes[subject.id].set_lambda_grad(self.Nodes[parent_nid].get_lambda_grad())
        else:
            self.Nodes[subject.id].setSubjTags([1.0, 1.0, 1.0, 1.0])
        return
        
    def set_subject_tags(self, nid):
        self.Nodes[nid].setSubjTags([1.0, 1.0, 1.0, 1.0])

    def reset_tags(self):
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            if isinstance(self.Nodes[nid], Subject):
                self.set_subject_tags(nid)
            else:
                self.set_object_tags(nid)
        
    def reset(self):
        # nid_list = list(self.Nodes.keys())
        # for nid in nid_list:
        #     self.Nodes[nid].updateTime = 0
        self.G = nx.DiGraph()
        self.Nodes = {}
        self.processes = {}
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]
