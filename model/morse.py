import numpy as np
import networkx as nx
import torch
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.initTags import match_path, match_network_addr
from policy.propTags import propTags
# from policy.alarms import check_alarm, check_alarm_pre, printTime
from model.loss_1 import check_alarm, check_alarm_pre, printTime
from parse.eventType import UNUSED_SET, EXIT_SET, UPDATE_SET, cdm_events


class Morse:

    def __init__(self, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0, alarm_file = './results/alarms.txt'):
        self.device = None
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
        if cdm_events[event['type']] in UPDATE_SET:
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            self.propagate(event, src, dest)
            return None, None, None, None, None, None, None, None, None
        if cdm_events[event['type']] in EXIT_SET:
            try:
                self.processes[self.Nodes[event['src']].pid]['alive'] = False
                # del self.Nodes[event['src']]
            except KeyError:
                # print('Oops! Cannot find Node!')
                return None, None, None, None, None, None, None, None, None
        if event['src'] != -1 and event['dest'] != -1:
            self.G.add_edge(event['src'], event['dest'])
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            if src and dest:
                if src.id == '674D8313-390A-11E8-BF66-D9AA8AFF4A69' or dest.id == '674D8313-390A-11E8-BF66-D9AA8AFF4A69':
                    stop = 0
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

                if diagnosis:
                    a = 0

                return diagnosis, s_loss, o_loss, s_tags, o_tags, s_grad, o_grad, s_init_id, o_init_id
        
        return None, None, None, None, None, None, None, None, None

    def add_event(self, event, gt=None):
        if event['src'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['src']] = True
        if event['dest'] in self.Initialized_Nodes:
            self.Initialized_Nodes[event['dest']] = True
        # if cdm_events[event['type']] in UNUSED_SET:
        #     return
        if cdm_events[event['type']] in UPDATE_SET:
            src = self.Nodes.get(event['src'], None)
            dest = self.Nodes.get(event['dest'], None)
            self.propagate(event, src, dest)
            return
        if cdm_events[event['type']] in EXIT_SET:
            try:
                self.processes[self.Nodes[event['src']].pid]['alive'] = False
                # del self.Nodes[event['src']]
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
    
    def set_object_tags(self, object_id):
        if self.Nodes[object_id].type in {"MemoryObject", "UnnamedPipeObject"}:
            obj_tag = [1.0, 1.0]
        elif self.Nodes[object_id].type in {"SrcSinkObject"}:
            obj_tag = [0.0, 1.0]

            # white_list = {'pulseaudio': 97817, 'mandb': 17744, 'indicator-sound': 13289, 'dpkg': 7616, 'apt-config': 4073, 'bash': 3325, 'date': 2331, 'dirname': 1797, 'uname': 1619, '50-landscape-sy': 1542, 'sshd': 1445, 'cat': 1298, 'grep': 1260, 'stat': 1059, 'cargo': 1041, 'find': 965, 'cut': 947, 'sh': 937, 'tail': 865, 'rm': 796, 'landscape-sysin': 759, 'lesspipe': 751, 'ls': 741, 'pool': 716, 'update-motd-fsc': 663, 'update-motd-hwe': 576, 'lsb_release': 518, 'expr': 505, '10-help-text': 475, 'update-motd-reb': 470, 'update-motd-upd': 467, '91-release-upgr': 459, 'bc': 452, 'run-parts': 405, 'who': 403, 'mktemp': 386, 'awk': 377, 'basename': 374, 'pkexec': 368, 'at-spi-bus-laun': 367, 'release-upgrade': 347, '00-header': 316, 'clear_console': 308, 'ldconfig.real': 293, 'firefox': 266, 'dircolors': 250, 'Web Content': 182, 'sudo': 166, 'thunderbird': 165, 'ssh': 158, 'xfce4-session': 134, 'wall': 117, 'scp': 88, 'which': 78, 'df': 69, 'mv': 66, 'dpkg-deb': 65, 'xvnc4viewer.pos': 58, 'sync': 57, 'ping': 45, 'netstat': 37, 'fiberlamp': 35, 'xfce4-appfinder': 34, 'man-db.postinst': 33, 'xscreensaver': 30, 'gvfs-udisks2-vo': 28, 'update-alternat': 28, 'sysctl': 28, 'xvnc4viewer.pre': 27, 'du': 27, 'xfce4-terminal': 26, 'salt-minion': 24, 'hostname': 24, 'dumpe2fs': 24, 'gvfsd-trash': 23, 'write': 21, 'indicator-bluet': 20, 'fuzzyflakes': 20, 'tar': 17, 'blueman-applet': 16, 'ps': 16, 'chsh': 16, 'dpkg-split': 16, 'whoami': 16, 'wget': 15, 'top': 14, 'apt-check': 14, 'hwe-support-sta': 14, 'update-notifier': 13, 'exo-open': 11, 'check-new-relea': 11, 'ImageIO': 10, 'xfsettingsd': 9, 'Thunar': 8, 'mkdir': 8, 'dmesg': 8, 'at-spi2-registr': 7, 'gvfsd': 7, 'indicator-appli': 6, 'autospawn': 5, 'nm-applet': 4, 'cron': 4, 'Socket Thread': 4, 'dconf-service': 4, 'ifconfig': 4, 'resolvconf': 4, 'gnome-pty-helpe': 4, 'mount': 4, 'sed': 4, 'uptime': 4, 'xfdesktop': 3, 'xfce4-power-man': 3, 'light-locker': 3, 'indicator-power': 3, 'xfwm4': 2, 'xfce4-panel': 2, 'gconfd-2': 2, 'gvfs-gphoto2-vo': 2, 'gvfs-afc-volume': 2, 'gvfs-mtp-volume': 2, 'nc': 1}
            white_list = {}

            pid = int(self.Nodes[object_id].name.split('_')[-1])
            # if pid in self.processes and self.Nodes[self.processes[pid]['node']].processName in {'sshd', 'firefox', 'xfce4-appfinder'}:
            # if pid in self.processes and self.Nodes[self.processes[pid]['node']].processName in {'sshd', 'salt-minion', 'pkexec'}:
            if pid in self.processes and self.Nodes[self.processes[pid]['node']].processName in white_list:
                obj_tag = [1.0, 1.0]
            else:
                obj_tag = [0.0, 1.0]
        elif self.Nodes[object_id].type in {"NetFlowObject"}:
            obj_tag = self.node_inital_tags[object_id]
        elif self.Nodes[object_id].type in {"FileObject"}:
            # obj_tag = self.node_inital_tags[object_id]

            obj_tag = list(match_path(self.Nodes[object_id].path))

            # obj_tag_prov = self.node_inital_tags[object_id]
            # obj_tag = []
            # if obj_tag_prov[0] > 0.5:
            #     obj_tag.append(1.0)
            # else:
            #     obj_tag.append(0.0)

            # if obj_tag_prov[1] > 0.5:
            #     obj_tag.append(1.0)
            # else:
            #     obj_tag.append(0.0)

            # obj_tag = [1.0, 1.0]
        else:
            # a = self.Nodes[object_id].type
            # obj_tag = self.node_inital_tags[object_id]
            obj_tag = [1.0, 1.0]
        self.Nodes[object_id].setObjTags(obj_tag)

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
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            if self.Initialized_Nodes[nid] == False:
                if isinstance(self.Nodes[nid], Subject):
                    # sub_tag = self.node_inital_tags[nid].tolist()
                    sub_tag = [1.0, 1.0, 1.0, 1.0]
                    self.Nodes[nid].setSubjTags(sub_tag)
                else:
                    self.set_object_tags(nid)
        
    def reset_morse(self):
        nid_list = list(self.Nodes.keys())
        for nid in nid_list:
            self.Initialized_Nodes[nid] = False
        self.alarm = {}
