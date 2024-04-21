import json
import random
import uuid
from tqdm import tqdm

## Strating Time of Detection
ts = 1523586247675522567

mimicry_subgraph_ts = 1523478987898404334

with open("adversarial/artifacts/cadets.json", "r") as json_file:
    GT_mal = set(json.load(json_file))

connected_edge = 0
target_insert_num = 12

# attack_entities = [('DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A', {"exec":"test", "ppid":"804"}),
#                  ('0001A528-3E80-11E8-A5CB-3FA3753A265A', {"exec":"test", "ppid":"804"}),
#                  ('327621AE-3E80-11E8-A5CB-3FA3753A265A', {"exec":"test", "ppid":"20691"}),
#                  ('47E61FFC-3E80-11E8-A5CB-3FA3753A265A', {"exec":"test","ppid":"20408"})]

attack_entities = [('84D440C2-4E50-4A5C-904E-C4772C4ACD5A', {"string":"/tmp/test"})]

## Open two files and the output file
with open('../data/raw/ta1-cadets-e3-official-2.json/ta1-cadets-e3-official-2.json', 'r') as file1, open('../data/raw/ta1-cadets-e3-official.json/ta1-cadets-e3-official.json.1', 'r') as file2, open('adversarial/artifacts/mimicry_logs.json', 'w') as outfile:
    for line1 in tqdm(file1):
        ## if line1 is not null，write line1
        if line1:
            data1 = json.loads(line1)
            # if "com.bbn.tc.schema.avro.cdm18.Event" in data1["datum"]:
            #     if data1["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["subject"] and\
            #         data1["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["subject"]["com.bbn.tc.schema.avro.cdm18.UUID"] in \
            #         {'DCBB8D5C-3E7F-11E8-A5CB-3FA3753A265A','0001A528-3E80-11E8-A5CB-3FA3753A265A','327621AE-3E80-11E8-A5CB-3FA3753A265A','47E61FFC-3E80-11E8-A5CB-3FA3753A265A'} and \
            #         data1["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["type"] == "EVENT_EXIT":
            #         continue
            if line1.endswith('\n') == False:
                line1 += '\n'
            outfile.write(line1)
    
    for line2 in tqdm(file2):
        ## if line2 is not null，write line2
        if line2:
            data2 = json.loads(line2)
            if "com.bbn.tc.schema.avro.cdm18.Event" in data2["datum"]:
                data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["timestampNanos"] = data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["timestampNanos"] - mimicry_subgraph_ts + ts
                # if random.randint(0, 50000) == 0:
                if True:
                    if data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["predicateObject"] and data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["type"] not in  {"EVENT_EXIT","EVENT_EXECUTE","EVENT_FORK","EVENT_CLONE","EVENT_MMAP"}:
                        if data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"] == '6EA02F1F-9233-1956-B392-D6210619CECF':
                            attack_subject = random.choice(attack_entities)
                            data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"] = attack_subject[0]
                            data2["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]["predicateObjectPath"] = attack_subject[1]
                            line3 = json.dumps(data2)+'\n'
                            outfile.write(line3.replace(' ', ''))
                            connected_edge += 1
                            if connected_edge == target_insert_num:
                                break
            else:
                line3 = json.dumps(data2)+'\n'
                outfile.write(line3.replace(' ', ''))
                # connected_edge += 1

print("Added {:,} edges to the attack graph!".format(connected_edge))
