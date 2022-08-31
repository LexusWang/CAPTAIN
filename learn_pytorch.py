import torch
import json

import numpy as np

a = [0.3, 0.3, 0.3]
# b = [0,0]
c = np.dot(a, a)

a = 40%10

a = {'sad':5, 'happy':6}
b = a
a['normal'] = 8

del a['sad']

a = {'Records': [{'messageId': 'a255bdcd-1c28-4c1e-a080-6120cbcebc10', 'receiptHandle': 'AQEBJi2hTBJ0FCXDdS0wQ+J7LJ1zWGPDC1rP140uwTOs9QCv6IB87npND+jGbqwfHs0nzq9yay/s9zSBlAj/6qPXSk0u2AUKw+UxZHBbLB6njXy34Ov5jW6sJn3YQJi+BU/JkpjhVA6jqYpso9ib1fl4dMvPdzL4oN0bM9DP1t2X3XbvsT0AjC1JJDBe56/U2MCPHOyFTReQWCj/9r+vOi4rE91YW7+kUmGXFLDb2RVZVccqserT9s6+khb9IbBzkF3KS1zs07T/3zItyIVNZ7hl+wpesytqjKrmDfH1LAZJ1RHuwMhsDQomeXU43QHDBDDh8Z2VbtvYMkZbSvpVGps/cnQPe2YAdlWsuyVnN0PrCCSi/bFXqYwO3FKs6/DOLy/I', 'body': '{"user_id": "0001", "timestamp": "092821120000", "mood": 2, "text": "I am having a really bad day..."}', 'attributes': {'ApproximateReceiveCount': '2152', 'SentTimestamp': '1651806907310', 'SenderId': 'AROAZSNLGIGR5AE23DTUO:user1936096=xchen97@uchicago.edu', 'ApproximateFirstReceiveTimestamp': '1651806907310'}, 'messageAttributes': {}, 'md5OfBody': '6dc22ff423a5668fe54a457ccc747bd7', 'eventSource': 'aws:sqs', 'eventSourceARN': 'arn:aws:sqs:us-east-1:658025890211:q1a_sqs', 'awsRegion': 'us-east-1'}]}

b = json.loads(a['Records'][0]['body'])

nn1 = torch.nn.Linear(5,1)

nn2 = torch.nn.Linear(5,1)

input_data1 = torch.tensor([[-4,4,7,1,5],[4,3,5,7,9]],dtype=torch.float32,requires_grad=True)

a = input_data1[0, :]

b = torch.tensor((1.0, 1.0))

input_data2 = torch.tensor([0],dtype=torch.float32,requires_grad=True)

a = input_data2.item()

b1 = torch.sigmoid(nn1.forward(input_data1))
b2 = torch.sigmoid(nn2.forward(input_data1))

a = b1 + b2



opti = torch.optim.Adam(nn.parameters(),lr=1e-1)

loss.backward()


opti.zero_grad()
a.backward(gradient=c.grad.unsqueeze(0))
opti.step()

b = torch.sigmoid(nn.forward(input_data))

opti.zero_grad()
b.backward(gradient=c.grad.unsqueeze(0))
opti.step()

d = torch.sigmoid(nn.forward(input_data))

c = 0