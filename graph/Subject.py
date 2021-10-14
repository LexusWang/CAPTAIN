# from morse import Morse
import numpy as np
import re


# from globals import GlobalVariable as gv


class Subject:
    def __init__(self, id = -1, time: float = -1.0, type: int = -1, subtype: int = -1, pid: int = -1, ppid: int = -1, cmdLine: str = None,
                 processName: str = None):
        self.id = id
        self.time = time
        self.type = type
        self.subtype = subtype
        self.pid = pid
        self.ppid = ppid
        self.cmdLine = cmdLine
        self.processName = processName
        self.updateTime = 0
        self.owner = None

        self.event_list = []
        self.event_id_list = []
        self.event_type_list = []
        self.state_list = []
        self.morse_grad_list = []
        self.simple_net_grad_list = []
        # grad list stores grad of morse
        self.cur_state = np.zeros([2, 3])
        self.seq_len = 0

        # init tags
        self.eTag: float = 0.0
        # init tags
        self.ciTag: float = 0.0
        # init tags
        self.invTag: float = 0.0
        # benign
        self.iTag: float = 0.0
        #
        self.cTag: float = 0.0

        self.ciTag_grad: float = 1.0
        self.eTag_grad: float = 1.0
        self.invTag_grad: float = 1.0
        self.iTag_grad: float = 1.0
        self.cTag_grad: float = 1.0

        self.ciTag_initID = id
        self.eTag_initID = id
        self.invTag_initID = id
        self.iTag_initID = id
        self.cTag_initID = id


        # if self.ppid == -1:
        #     pass
        #     # unknown parent
        #     # self.sTag = morse.get_stag_dangerous()
        # elif self.ppid == 0:
        #     pass
        #     # process generated by root
        #     # self.sTag = morse.get_stag_benign()
        # else:
        #     parent_id = gv.get_processNode_by_pid(self.ppid)
        #     parent_node = gv.get_processNode(parent_id)
        #     if not parent_node:
        #         # parent node not exist or has been released, then this node is not valid
        #         self.sTag = morse.get_stag_dangerous()
        #         self.iTa = morse.get_itag_dangerous()
        #         self.cTag = morse.get_ctag_dangerous()
        #     else:
        #         self.sTag = parent_node.sTag
        #         self.iTag = parent_node.iTag
        #         self.cTag = parent_node.cTag

    def get_id(self):
        return self.id
    
    def get_pid(self):
        return self.pid

    def get_name(self):
        return self.processName

    def get_cmdln(self):
        return self.cmdLine

    def tags(self):
        return [self.ciTag, self.eTag, self.invTag, self.iTag, self.cTag]

    def setSubjTags(self,tags):
        self.ciTag = tags[0]
        self.eTag = tags[1]
        self.invTag = tags[2]
        self.iTag = tags[3]
        self.cTag = tags[4]

    def get_grad(self):
        return [self.ciTag_grad, self.eTag_grad, self.invTag_grad, self.iTag_grad, self.cTag_grad]

    def get_citag_grad(self):
        return self.ciTag_grad

    def get_etag_grad(self):
        return self.eTag_grad

    def get_invtag_grad(self):
        return self.invTag_grad

    def get_itag_grad(self):
        return self.iTag_grad

    def get_ctag_grad(self):
        return self.cTag_grad

    def set_grad(self, grads):
        self.ciTag_grad = grads[0]
        self.eTag_grad = grads[1]
        self.invTag_grad = grads[2]
        self.iTag_grad = grads[3]
        self.cTag_grad = grads[4]

    def update_grad(self, grads):
        self.ciTag_grad *= grads[0]
        self.eTag_grad *= grads[1]
        self.invTag_grad *= grads[2]
        self.iTag_grad *= grads[3]
        self.cTag_grad *= grads[4]

    def setciTagInitID(self, id):
        self.ciTag_initID = id

    def seteTagInitID(self, id):
        self.eTag_initID = id

    def setinvTagInitID(self, id):
        self.invTag_initID = id

    def setiTagInitID(self, id):
        self.iTag_initID = id

    def setcTagInitID(self, id):
        self.cTag_initID = id

    def getInitID(self):
        return [self.ciTag_initID, self.eTag_initID, self.invTag_initID, self.iTag_initID, self.cTag_initID]

    def getciTagInitID(self):
        return self.ciTag_initID

    def geteTagInitID(self):
        return self.eTag_initID

    def getinvTagInitID(self):
        return self.invTag_initID

    def getiTagInitID(self):
        return self.iTag_initID

    def getcTagInitID(self):
        return self.cTag_initID

    def isMatch(self, string):
        if self.processName == None:
            return False
        return isinstance(re.search(string, self.processName), re.Match)

    def get_matrix_array(self, padding: 4):
        if padding < 4:
            return None

        return [self.subtype, self.sTag, self.iTag, self.cTag] + [0] * (padding - 4)

    def add_event(self, event_id: int, event_type: int):
        # print(event_id)
        self.event_list.append(event_id)
        self.event_type_list.append(event_type)

    def get_event_list(self) -> list:
        return self.event_list

    def get_event_id_list(self) -> list:
        return self.event_id_list

    def get_event_type_list(self) -> list:
        return self.event_type_list

    def state_update(self, state: np.array, event_type: int, event: np.array, morse_grad: np.ndarray, simple_net_grad: np.ndarray, event_id: int = None):
        if event_id is not None:
            self.cur_state = state
            # cur_state(12)

            self.state_list.append(state)
            self.event_list.append(event)
            # event(4,4)

            self.event_id_list.append(event_id)
            self.morse_grad_list.append(morse_grad)
            # morse_grad(12, 2)

            self.simple_net_grad_list.append(simple_net_grad)
            # simple_net_grad(12, 4)

            self.event_type_list.append(event_type)
            self.seq_len += 1

    def generate_sequence_and_grad(self, batch_size=100, sequence_size=5):
        """
        :param batch_size: how many sequences in a batch
        :param sequence_size: how long a sequence is
        :return: a batch of sequences and their grads
        """
        if self.seq_len < sequence_size:
            return [[], [], []]
        res = []
        morse_grad_res = []
        simple_net_grad_res = []
        total_len = min(batch_size, self.seq_len - sequence_size + 1)
        for i in range(total_len):
            res.append(self.state_list[i:i + sequence_size])
            morse_grad_res.append(self.morse_grad_list[i:i + sequence_size])
            simple_net_grad_res.append(self.simple_net_grad_list[i:i + sequence_size])
        # if total_len < batch_size:
        #     res += [[]] * (batch_size - total_len)
        # print(np.shape(morse_grad_res))
        return [res, morse_grad_res, simple_net_grad_res]

    def generate_sequence(self, batch_size=100, sequence_size=5):
        """
        :param batch_size: how many sequences in a batch
        :param sequence_size: how long a sequence is
        :return: a batch of sequences
        """
        if self.seq_len < sequence_size:
            return []
        res = []
        total_len = min(batch_size, self.seq_len - sequence_size + 1)
        for i in range(total_len):
            res.append(self.state_list[i:i + sequence_size])
        return res

    def generate_simple_net_grad_sequence(self, batch_size=100, sequence_size=5):
        """
        :param batch_size: how many sequences in a batch
        :param sequence_size: how long a sequence is
        :return: a batch of sequences
        """
        if self.seq_len < sequence_size:
            return [[], []]
        res = []
        total_len = min(batch_size, self.seq_len - sequence_size + 1)
        for i in range(total_len):
            res.append(self.grad_list[i:i + sequence_size])
        # if total_len < batch_size:
        #     res += [[]] * (batch_size - total_len)
        return res
