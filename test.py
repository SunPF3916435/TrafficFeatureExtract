import FlowFeature
from pcap_splitter.splitter import PcapSplitter


#ps = PcapSplitter('BotNetTraffic/botnet-traffic-1.pcap')
#print(ps.split_by_session('BotNetTrafficFlow', pkts_bpf_filter='tcp'))


feature = FlowFeature.Extract('TrafficFLow', [1, 2, 3, 5, 6, 15], 5)
feature.write_csv()
#print(feature.ip_total_length_for_every_packet())


