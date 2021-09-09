import numpy as np
import networkx as nx
import torch
import sys
sys.path.extend(['.','..','...'])
from graph.Subject import Subject
from graph.Object import Object
from policy.initTags import initObjectTags, initSubjectTags
from policy.propTags import propTags
from policy.alarms import check_alarm


class Morse:

    def __init__(self, format= 'cdm', batch_size = 0, sequence_size = 0, data_loader = 0):

        self.batch_size = batch_size
        self.sequence_size = sequence_size
        self.data_loader = data_loader

        self.format = format

        # init graph
        self.G = nx.DiGraph()
        self.Nodes = {}
        # self.Objects = {}

        # init value
        self.stag_benign = 0.5
        self.stag_suspect_env = 0.25
        self.stag_dangerous = 0.2
        self.itag_benign = 0.5
        self.itag_suspect_env = 0.25
        self.itag_dangerous = 0.2
        self.ctag_benign = 0.5
        self.ctag_suspect_env = 0.25
        self.ctag_dangerous = 0.2

        # threshold
        self.benign = 0.5
        self.suspect_env = 0.25

        # decay and attenuation
        self.a_b = 0.1
        self.a_e = 0.05

        # alarm
        self.alarm = {}
        self.created = {}
        self.alarm_sum = [0, 0]

        # # scaler w and b
        # self.benign_thresh_model = simple_net.SimpleNet()
        # # scaler w and b
        # self.suspect_env_model = simple_net.SimpleNet()

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


    # def forward(self, learn):
    #     # feed forward, get the predicted result

    #     # generate sequence


    #     simple_net_final_grad_of_multiple_batches = []
    #     final_morse_grad_of_multiple_batches = []
    #     forward_result_batches = []

    #     for node_id in self.data_loader:
    #         node = self.data_loader[node_id]
    #         [sequence, morse_grad, simple_net_grad] = node.generate_sequence_and_grad(self.batch_size,
    #                                                                                   self.sequence_size)
    #         # sequence: (?, 5, 12)
    #         # morse_grad: (?, 5, 12, 2)
    #         # simple_net_grad: (?, 5, 12, 4)

    #         need = self.batch_size - self.cur_len

    #         if len(sequence) + self.cur_len > self.batch_size:
    #             self.cur_batch += sequence[:need]
    #             self.cur_simple_net_grad_list += simple_net_grad[:need]
    #             self.cur_morse_grad_list += morse_grad[:need]
    #             self.cur_len = self.batch_size
    #             self.cur_event_type_list += node.event_type_list[:need]
    #             self.cur_event_list += node.event_list[:need]

    #             remain_batch = sequence[need:]
    #             remain_event_list = node.event_list[need:]
    #             remain_event_type_list = node.event_type_list[need:]
    #             remain_simple_net_grad_list = simple_net_grad[need:]
    #             remain_morse_grad_list = morse_grad[need:]
    #         else:
    #             self.cur_batch += sequence[:need]
    #             self.cur_morse_grad_list += morse_grad[:need]
    #             self.cur_simple_net_grad_list += simple_net_grad[:need]
    #             self.cur_len += len(sequence)
    #             self.cur_event_type_list += node.event_type_list[:need]
    #             self.cur_event_list += node.event_list[:need]
    #         # batch_size * sequence_size * feature _size
    #         # batch_size: 100
    #         # sequence_size: 5
    #         # feature_size: 12
    #         # 100*5*12

    #         # print("creating batch")
    #         if self.cur_len >= self.batch_size:
    #             # print("cur_batch, size: ", np.shape(cur_batch), len(cur_batch[0][0]), cur_batch)
    #             input_tensor = torch.tensor(self.cur_batch)
    #             self.simple_net_grad_tensor = torch.tensor(self.cur_simple_net_grad_list, dtype=torch.float)
    #             self.morse_grad_tensor = torch.tensor(self.cur_morse_grad_list, dtype=torch.float)

    #             # input_tensor: (100, 5, 12)
    #             # morse_grad_tensor: (100, 5, 12, 2)
    #             # simple_net_grad_tensor: (100, 5, 12, 4)

    #             # print("getting into RNN")

    #             # input size: 100 * 5 * 12
    #             # output size: 100 * 5 * 12

    #             # final_grad = morse_train.back_propagate(input_tensor, event_type_list, event_list, rnn_grad)
    #             # print(final_grad)
    #             # # update weights
    #             # self.a_b_setter(-learn * final_grad[0])
    #             # self.a_e_setter(-learn * final_grad[1])
    #             # self.benign_thresh_model_setter(final_grad[2])
    #             # self.suspect_env_model_setter(final_grad[3])

    #             self.cur_batch = self.remain_batch[::]
    #             self.cur_morse_grad_list = self.remain_morse_grad_list[::]
    #             self.cur_simple_net_grad_list = self.remain_simple_net_grad_list[::]
    #             self.cur_event_type_list = self.remain_event_type_list[::]
    #             self.cur_event_list = self.remain_event_list[::]
    #             self.cur_len = len(self.cur_batch)

    #             self.remain_batch = []
    #             self.remain_event_list = []
    #             self.remain_event_type_list = []
    #             self.remain_morse_grad_list = []
    #             self.remain_simple_net_grad_list = []

    #             forward_result_batches.append(input_tensor)
    #             # return input_tensor

    #             # print(type(simple_net_grad_tensor), type(rnn_grad))
    #             # calculate the final grads of loss wrt w,b in simple_net by
    #             # combining grads from simple_net and grads from rnn

    #             # print(rnn_grad.is_cuda)
    #             # print(simple_net_grad_tensor.is_cuda)

    #     # self.data_loader.pos = 0
    #     return forward_result_batches


    #     # if len(simple_net_final_grad_of_multiple_batches) > 0:
    #     #     average_final_simplenet_grads = sum(simple_net_final_grad_of_multiple_batches) / len(
    #     #         simple_net_final_grad_of_multiple_batches)
    #     #     average_final_morse_grads = sum(final_morse_grad_of_multiple_batches) / len(
    #     #         final_morse_grad_of_multiple_batches)
    #     #     self.a_b_setter(-learn * average_final_morse_grads[0])
    #     #     self.a_e_setter(-learn * average_final_morse_grads[1])
    #     #
    #     #     # update SimpleNet's weights
    #     #     self.benign_thresh_model_setter(average_final_simplenet_grads[0], average_final_simplenet_grads[1])
    #     #     self.suspect_env_model_setter(average_final_simplenet_grads[2], average_final_simplenet_grads[3])

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


    def propagate(self, event, s, o):
        propTags(event, s, o, format=self.format)

    def add_event(self, event):
        self.G.add_edge(event['src'], event['dest'])
        src = self.Nodes.get(event['src'], None)
        dest = self.Nodes.get(event['dest'], None)
        if src and dest:
            self.propagate(event, src, dest)
            self.detect_alarm(event, src, dest)

    def add_object(self, object_node, object):
        self.G.add_node(object_node['uuid'])
        # self.G.nodes[object_node['uuid']]['tags'] = object_node['tags']
        initObjectTags(object)
        self.Nodes[object_node['uuid']] = object

    def add_subject(self, subject_node, subject):
        self.G.add_node(subject_node['uuid'])
        # self.G.nodes[subject_node['uuid']]['tags'] = subject_node['tags']
        initSubjectTags(subject)
        self.Nodes[subject_node['uuid']] = subject

    def detect_alarm(self,event,s ,o):
        self.alarm[(s.get_pid(), o.get_name())] = False
        check_alarm(event, s, o, self.alarm, self.created, self.alarm_sum, format=self.format)
        
