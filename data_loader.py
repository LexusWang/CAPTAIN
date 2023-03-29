import avro.schema
from avro.datafile import DataFileReader, DataFileWriter
from avro.io import DatumReader, DatumWriter

schema = avro.schema.parse(open("/Users/lexus/Documents/research/APT/Data/raw/E3/schema/TCCDMDatum.avsc", "rb").read())

# writer = DataFileWriter(open("users.avro", "wb"), DatumWriter(), schema)
# writer.append({"name": "Alyssa", "favorite_number": 256})
# writer.append({"name": "Ben", "favorite_number": 7, "favorite_color": "red"})
# writer.close()

reader = DataFileReader(open("/Users/lexus/Documents/research/APT/Data/raw/E3-cadets-2/ta1-cadets-e3-official-1.bin/ta1-cadets-e3-official-1.bin", "rb"), DatumReader())
for user in reader:
    print(user)
reader.close()