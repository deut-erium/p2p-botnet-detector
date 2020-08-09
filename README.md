# Botnet Detection

## Team IITBreachers
### Himanshu Sheoran
### Lakshay Kumar

## Submission format

### [botnetdetect.py](botnetdetect.py)
The main program
#### Usage

##### Botnet detection
python3 botnetdetect.py <path to pcap file>

Processes pcap file to produce `extracted_features.csv` which contains the features extracted from the pcap
> NOTE: feature extraction is slow depending upon the size of input pcap (approx 1 minute to process 10MB)

results are stored in `output.txt`

##### Train model
python3 botnetdetect.py train model_name
> Assumption: The current directory contains training data in directory `Botnet_Detection_Dataset`

Generates filtered csv files in `filtered_data` directory in current working directory

#### Result format

If no botnet is detected, the result would be
**No Botnets detected** in a single line
Otherwise

**----------Detected Botnet Hosts----------** 
host1
host2
...
host n
**----------Malicious Flows----------**
source ip1:source port1 -> destination ip1:destination port1 ; protocol
source ip2:source port2 -> destination ip2:destination port2 ; protocol
...
source ipn:source portn -> destination ipn:destination portn ; protocol




### [trained_model.pickle](trained_model.pickle)
pretrained model

### [training.csv](tranining.csv)
csv file containing the features extracted from training data

### [dependencies]
```
sudo apt-get install wireshark
sudo apt-get install -y tshark
sudo apt-get install libmagic-dev
pip3 install -r requirements.txt
```

- wireshark
- tshark
- libmagic-dev
- python3.8 (should work on 3.6 above)
  - pyshark
  - nest_asyncio
  - python-magic
  - numpy
  - pandas
  - tqdm
  - sklearn


## Features used and extracted
| Feature                    | description                              | is metadata?|
| -------                    | ------------                             | ----------- |
|src_ip                      | source of flow                           |1|
|src_port                    | port of source                           |1|
|dst_ip                      | destination of flow                      |1|
|dst_port                    | port of destination                      |1|
|protocol                    | protocol used                            |1|
|total_data                  | total data exchanged (including headers) |0|
|sent_packets                | total packets sent                       |0|
|recv_packets                | total packets recieved                   |0|
|sent_data                   | total data sent                          |0|
|recv_data                   | total data recieved                      |0|
|total_sent_payload          | total payload sent                       |0|
|total_recv_payload          | total payload recieved                   |0|
|max_payload_size            | maximum size of payload                  |0|
|max_payload_entropy         | maximum entropy of payload               |0|
|min_payload_size            | minimum size of payload                  |0|
|min_payload_entropy         | minimum entropy of payload               |0|
|net_entropy                 | entropy of all payload combined          |0|
|average_payload_size        | average size of payload                  |0|
|average_packet_length       | average size of packet                   |0|
|average_packet_per_sec      | average number of packets per second     |0|
|average_packet_size_per_sec | average data transer rate                |0|
|num_protocols               | number of protocols used                 |0|
|total_time                  | total time of flow                       |0|
|incoming_outgoing_ratio     | ratio of incoming vs outgoing data rate  |0|
|num_small_packets           | number of small size packets transferred |0|
|label                       | label of flow                            |1|
