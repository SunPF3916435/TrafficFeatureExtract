import scapy.all
import os
import numpy as np


class Extract:
    def __init__(self, Directory, feature_label, k=5):
        self.Directory = Directory  # flow directory
        self.feature_label = feature_label  # [1, 4, 6, 7, 8]
        self.k = k  # top-k packet
        self.Flows = self.read_flows_from_files()  # take traffic in a list[]
        self.flows_num = self.flow_num()  # flow num
        self.packets_num = self.packet_num()  # packet num in every flow
        self.client_packet_num = self.statistic_client_packet_num()
        self.server_packet_num = self.statistic_server_packet_num()
        self.feature = self.select_concat_feature()  # feature

    ###########################################################################
    def read_flows_from_files(self):  # this function is for reading pacp
        Flows = []
        for dirpath, dirnames, filenames in sorted(os.walk(self.Directory)):
            for file in filenames:
                flow = scapy.all.rdpcap(os.path.join(dirpath, file))
                Flows.append(flow)
        return Flows

    def flow_num(self):  # for getting flow num
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(self.Directory):
            for file in filenames:
                file_count = file_count + 1
        return file_count

    def select_concat_feature(self):  # for generate feature and concat to be a matrix
        feature = np.arange(0, self.flows_num)
        feature = np.expand_dims(feature, axis=1)
        for label in self.feature_label:
            if label == 1:
                packet_num = np.array(self.packet_num())
                packet_num = np.expand_dims(packet_num, axis=1)
                feature = np.hstack((feature, packet_num))
                print('Finished extracting the {} feature.'.format(label))
            if label == 2:
                ip_minimum_total_length = np.array(self.ip_minimum_total_length_for_every_flow())
                ip_minimum_total_length = np.expand_dims(ip_minimum_total_length, axis=1)
                feature = np.hstack((feature, ip_minimum_total_length))
                print('Finished extracting the {} feature.'.format(label))
            if label == 3:
                ip_maximum_total_length = np.array(self.ip_maximum_total_length_for_every_flow())
                ip_maximum_total_length = np.expand_dims(ip_maximum_total_length, axis=1)
                feature = np.hstack((feature, ip_maximum_total_length))
                print('Finished extracting the {} feature.'.format(label))
            if label == 4:
                ip_median_total_length = np.array(self.ip_median_total_length_for_every_flow())
                ip_median_total_length = np.expand_dims(ip_median_total_length, axis=1)
                feature = np.hstack((feature, ip_median_total_length))
                print('Finished extracting the {} feature.'.format(label))
            if label == 5:
                ip_mean_total_length = np.array(self.ip_mean_total_length_for_every_flow())
                ip_mean_total_length = np.expand_dims(ip_mean_total_length, axis=1)
                feature = np.hstack((feature, ip_mean_total_length))
                print('Finished extracting the {} feature.'.format(label))
            if label == 6:
                ip_variance_total_length = np.array(self.ip_variance_total_length_for_every_flow())
                ip_variance_total_length = np.expand_dims(ip_variance_total_length, axis=1)
                feature = np.hstack((feature, ip_variance_total_length))
                print('Finished extracting the {} feature.'.format(label))
            if label == 7:
                client_packet_num = np.array(self.statistic_client_packet_num())
                client_packet_num = np.expand_dims(client_packet_num, axis=1)
                feature = np.hstack((feature, client_packet_num))
                print('Finished extracting the {} feature.'.format(label))
            if label == 8:
                server_packet_num = np.array(self.statistic_server_packet_num())
                server_packet_num = np.expand_dims(server_packet_num, axis=1)
                feature = np.hstack((feature, server_packet_num))
                print('Finished extracting the {} feature.'.format(label))
            if label == 9:
                client_server_rate = np.array(self.client_packet_num_divide_server_packet_num())
                client_server_rate = np.expand_dims(client_server_rate, axis=1)
                feature = np.hstack((feature, client_server_rate))
                print('Finished extracting the {} feature.'.format(label))
            if label == 10:
                minimum_time_interval = np.array(self.minimum_time_interval())
                minimum_time_interval = np.expand_dims(minimum_time_interval, axis=1)
                feature = np.hstack((feature, minimum_time_interval))
                print('Finished extracting the {} feature.'.format(label))
            if label == 11:
                maximum_time_interval = np.array(self.maximum_time_interval())
                maximum_time_interval = np.expand_dims(maximum_time_interval, axis=1)
                feature = np.hstack((feature, maximum_time_interval))
                print('Finished extracting the {} feature.'.format(label))
            if label == 12:
                mean_time_interval = np.array(self.mean_time_interval())
                mean_time_interval = np.expand_dims(mean_time_interval, axis=1)
                feature = np.hstack((feature, mean_time_interval))
                print('Finished extracting the {} feature.'.format(label))
            if label == 13:
                client_ack_num = np.array(self.client_ack_num())
                client_ack_num = np.expand_dims(client_ack_num, axis=1)
                feature = np.hstack((feature, client_ack_num))
                print('Finished extracting the {} feature.'.format(label))
            if label == 14:
                server_ack_num = np.array(self.server_ack_num())
                server_ack_num = np.expand_dims(server_ack_num, axis=1)
                feature = np.hstack((feature, server_ack_num))
                print('Finished extracting the {} feature.'.format(label))
            if label == 15:
                top_k_ip_total_length = np.array(self.statistic_top_k_ip_total_length())
                print('Finished extracting the {} feature.'.format(label))
                feature = np.hstack((feature, top_k_ip_total_length))
        return feature

    def write_csv(self):  # write feature matrix in a csv
        np.savetxt('feature.csv', self.feature, delimiter=',')

    ###########################################################################

    # 1 get packet num for every flow
    def packet_num(self):
        pkt_num = []
        for i in range(self.flows_num):
            pkt_num.append(len(self.Flows[i]))
        return pkt_num

    # get source port and destination port(no use)
    def port(self):
        port = np.zeros((self.flows_num, 2))
        for idx in range(self.flows_num):
            port[idx][0] = self.Flows[idx][0].sport
            port[idx][1] = self.Flows[idx][0].dport
        return port

    # every packet' length return a list[] including numpy arrays including length for packet
    def ip_total_length_for_every_packet(self):
        ip_total_length = []
        for i in range(self.flows_num):
            pkt_length = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                pkt_length[j] = self.Flows[i][j].len
            ip_total_length.append(pkt_length)
        return ip_total_length  # return a[x][y], x is flows quantity, y is packets quantity in every flow.

    # 2
    def ip_minimum_total_length_for_every_flow(self):
        minimum_total_length = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            temp = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                temp[j] = self.Flows[i][j].len
            minimum_total_length[i] = np.min(temp)
        return minimum_total_length

    # 3
    def ip_maximum_total_length_for_every_flow(self):
        maximum_total_length = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            temp = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                temp[j] = self.Flows[i][j].len
            maximum_total_length[i] = np.max(temp)
        return maximum_total_length

    # 4
    def ip_median_total_length_for_every_flow(self):
        median_total_length = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            temp = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                temp[j] = self.Flows[i][j].len
            # print(temp)
            median_total_length[i] = np.median(temp)
        return median_total_length

    # 5
    def ip_mean_total_length_for_every_flow(self):
        mean_total_length = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            temp = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                temp[j] = self.Flows[i][j].len
            # print(temp)
            mean_total_length[i] = np.mean(temp)
        return mean_total_length

    # 6
    def ip_variance_total_length_for_every_flow(self):
        variance_total_length = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            temp = np.zeros(self.packets_num[i])
            for j in range(self.packets_num[i]):
                temp[j] = self.Flows[i][j].len
            # print(temp)
            variance_total_length[i] = np.var(temp)
        return variance_total_length

    # 7
    def statistic_client_packet_num(self):
        client_packet_num = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            client_port = self.Flows[i][0].sport
            for j in range(self.packets_num[i]):
                if self.Flows[i][j].sport == client_port:
                    client_packet_num[i] = client_packet_num[i] + 1
        return client_packet_num

    # 8
    def statistic_server_packet_num(self):
        server_packet_num = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            server_port = self.Flows[i][0].dport
            for j in range(self.packets_num[i]):
                if self.Flows[i][j].sport == server_port:
                    server_packet_num[i] = server_packet_num[i] + 1
        return server_packet_num

    # 9
    def client_packet_num_divide_server_packet_num(self):
        return self.client_packet_num / self.server_packet_num

    # 10
    def minimum_time_interval(self):
        minimum_time_interval = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            time_interval = np.zeros(self.packets_num[i] - 1)
            for j in range(self.packets_num[i]):
                if j == 0:
                    continue
                time_interval[j - 1] = self.Flows[i][j].time - self.Flows[i][j - 1].time
            minimum_time_interval[i] = np.min(time_interval)
        return minimum_time_interval

    # 11
    def maximum_time_interval(self):
        maximum_time_interval = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            time_interval = np.zeros(self.packets_num[i] - 1)
            for j in range(self.packets_num[i]):
                if j == 0:
                    continue
                time_interval[j - 1] = self.Flows[i][j].time - self.Flows[i][j - 1].time
            maximum_time_interval[i] = np.max(time_interval)
        return maximum_time_interval

    # 12
    def mean_time_interval(self):
        mean_time_interval = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            time_interval = np.zeros(self.packets_num[i] - 1)
            for j in range(self.packets_num[i]):
                if j == 0:
                    continue
                time_interval[j - 1] = self.Flows[i][j].time - self.Flows[i][j - 1].time
            mean_time_interval[i] = np.mean(time_interval)
        return mean_time_interval

    # 13
    def client_ack_num(self):
        client_ack_num = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            client_port = self.Flows[i][0].sport
            for j in range(self.packets_num[i]):
                if self.Flows[i][j].sport == client_port:
                    if self.Flows[i][j].ack != 0:
                        client_ack_num[i] = client_ack_num[i] + 1
        return client_ack_num

    # 14
    def server_ack_num(self):
        server_ack_num = np.zeros(self.flows_num)
        for i in range(self.flows_num):
            server_port = self.Flows[i][0].dport
            for j in range(self.packets_num[i]):
                if self.Flows[i][j].sport == server_port:
                    if self.Flows[i][j].ack != 0:
                        server_ack_num[i] = server_ack_num[i] + 1
        return server_ack_num

    # 15
    def statistic_top_k_ip_total_length(self):
        packet_length = self.ip_total_length_for_every_packet()
        top_k_ip_total_length = np.zeros((self.flows_num, self.k))

        for i in range(self.flows_num):
            count = 0
            if self.packets_num[i] >= self.k:
                for j in range(self.packets_num[i]):
                    top_k_ip_total_length[i][j] = packet_length[i][j]
                    count = count + 1
                    if count == self.k:
                        break
            else:
                for j in range(self.packets_num[i]):
                    top_k_ip_total_length[i][j] = packet_length[i][j]
        return top_k_ip_total_length


#

'''
test
'''
# flows = Extract('TrafficFlow', [1, 2, 3, 9, 10, 11, 12])
# flows.write_csv()
# port = flows.port()
# ip_total_length = flows.ip_total_length_for_every_packet()
# ip_min_length = flows.ip_minimum_total_length_for_every_flow()
# ip_max_length = flows.ip_maximum_total_length_for_every_flow()
# ip_median_length = flows.ip_median_total_length_for_every_flow()
# ip_mean_length = flows.ip_mean_total_length_for_every_flow()
# ip_variance_length = flows.ip_variance_total_length_for_every_flow()
# statistic_client_num = flows.statistic_client_packet_num()
# statistic_server_num = flows.statistic_server_packet_num()
# divide = flows.client_packet_num_divide_server_packet_num()
# min_time_interval = flows.minimum_time_interval()
# max_time_interval = flows.maximum_time_interval()
# mean_time_interval = flows.mean_time_interval()
# print(flows.Flows[1][6].show())
# print(ip_total_length)
# print(flows.packets_num)
# print(ip_min_length)
# print(ip_max_length)
# print(ip_median_length)
# print(ip_mean_length)
# print(ip_variance_length, 'variance')
# print(statistic_client_num)
# print(statistic_server_num)
# print(divide)
# print(min_time_interval)
# print(max_time_interval)
# print(mean_time_interval)