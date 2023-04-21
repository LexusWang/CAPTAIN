import pdb
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

        self.white_name_set = set()
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


    def propagate(self, event, s, o1, o2):
        propTags(event, s, o1, o2)

    def add_event_generate_loss(self, event, gt):
        diagnosis = None
        s_labels = []
        o_labels = []

        if event.type == 'exit':
            try:
                self.processes[self.Nodes[event.src].pid]['alive'] = False
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None

        src = self.Nodes.get(event.src, None)
        dest = self.Nodes.get(event.dest, None)
        dest2 = self.Nodes.get(event.dest2, None)

        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            alarmArg = self.detect_alarm_pre(event, src, dest, self.alarm_file)
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

            self.propagate(event, src, dest, dest2)

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
        dest2 = self.Nodes.get(event.dest2, None)
        # if event.id in {'07572653-5D4D-C16F-7828-10F27CC36EBA', 'A6EB4FFA-215B-5B10-4399-EA3EF85A9CB0', 'EF1372CE-4B1D-8308-BD33-B03C43997B63', '695DC396-AA5E-9BF2-3048-FD6DFD3B1F71', 'D30CDF97-8B16-AD29-402B-D1982EC60B03', '2F6DD6A1-E13B-A3DA-54A1-853D11A3E008', 'A23BA714-15F7-18FA-1932-E410C3139F66', '5A18C561-9EAD-78E8-660F-14A4B6591CB0', '24867A41-F66B-5B4A-8BCF-C8AE808A3FBB', '1C7875F7-7184-9BF8-4B97-E159A700606A', '54D5544D-73B7-EAD0-F50A-AF62175F4224', '44EDF5DF-C6D0-458B-750A-F3E0307E6854', 'AA72BC47-A8F4-A5DC-946B-EE3670764744', '31EFF667-796F-E3ED-6A26-F1DB93406D18', '706884A8-1536-C384-E704-CB97E3EA732F', '87DA52DF-6408-2D6D-7429-1BAAE4571FFF', 'B0B3F068-35C9-9D4C-3C30-4EF238B40FEA', '7D188D01-9471-2052-4BC6-C60C86BA8FDE', '3E2BEA41-1EAE-BEA3-02EE-EB27050BA447', 'CCBE3DC0-AEB4-52D0-13A7-758C5F9FDC73', 'FE9420DC-AB6F-D0DF-F8F7-04042244AC3F', '61D8F096-B6A6-8480-B916-7FB9ECA4FEDF', '120A8A1E-5579-514C-111B-FF10E0ADF7B1', '8EB9601E-0874-90DE-0B2C-36725E17DE2A', 'AC2F858F-1910-F5C9-2F05-31862513F6D5', '4AA52CEA-4D40-2C93-E33F-FF060542F02C', '77D01808-8E78-7C54-761B-258393AE1302', 'E743FEEB-826B-B220-EA8F-7A1A47CE2417', '230C8639-9E9E-CCA2-6BB0-C62267DE63C8', 'AD885DB8-384E-1AAF-0917-1A0712C1FDC9', 'B38FAE09-1AB6-E5AF-E3F4-1261ED56A469', '98A9712D-FB6B-8F58-B4C6-8BBACFA87004', 'DF03A2BC-300B-5159-CE85-9ED19D2DCF76', '81F8AD0C-C951-529C-0911-8ABAA8BCB6F7', '59A0B085-C2EC-FC4C-B05B-A09258CABF53', 'F3C3DCC2-75A9-5814-A4EF-923C02C0EF12', '54FB0E9E-7E07-7759-5EE1-FB0008B89482', '3332AB8C-EAFD-4A32-FBB5-10C193944E58', 'C0D187AE-986B-4343-C2EE-24E018768195', '3F6A9FD7-EFE3-9DA9-DDC7-9C6DDBC4D50D', '2AF06331-DAB9-9A11-59EE-A0AC24ABBB2F', '21BA2E8D-0242-9D31-D20B-A0727F98566D', '134BBCD2-ADF4-C997-04E0-F4C6D533658A', '378EC429-30F3-BAC8-59D3-B02EF7FBFDD4', 'B6DC3327-B3BB-1460-F619-08BF75B7EDA2', '7A830283-771A-1497-1BE7-A8745EDBC1E6', '17A6BBE3-0411-FFE8-C55D-56AFBFBE9658', '0F8CF745-900F-206D-F134-28686757C4D5', '9C30F412-AA0B-2DF9-9445-C9ECA11B6B2B', '320D92E7-F856-586A-3537-9E6D4EFAEE35', '6F7BBBD7-7EEB-08A6-DC89-86C0A453E239', '0BACDE0A-92BE-2A3E-0586-9E0A87F5E307'}:
        #     pdb.set_trace()

        if src:
            if dest and (src.get_pid(), dest.get_name()) not in self.alarm:
                self.alarm[(src.get_pid(), dest.get_name())] = False
            alarmArg = self.detect_alarm_pre(event, src, dest, self.alarm_file)
            self.propagate(event, src, dest, dest2)
            diagnosis = self.detect_alarm(event, src, dest, alarmArg, gt, self.alarm_file)
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
        

    def detect_alarm_loss(self,event,s ,o, alarmArg, gt, alarm_file = None):
        return check_alarm_loss(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, gt, self.format, self, alarm_file)

    def detect_alarm_pre_loss(self,event,s ,o, alarm_file = None):
        return check_alarm_pre_loss(event, s, o, self.alarm, self, alarm_file)

    def detect_alarm(self,event,s ,o, alarmArg, gt, alarm_file = None):
        return check_alarm(event, s, o, self.alarm, self.created, self.alarm_sum, alarmArg, gt, self.format, self, alarm_file)

    def detect_alarm_pre(self,event,s ,o, alarm_file = None):
        return check_alarm_pre(event, s, o, self.alarm, self, alarm_file)

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
