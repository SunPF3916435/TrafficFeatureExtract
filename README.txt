feature = FlowFeature.Extract('TrafficFlow', [1, 15], 10)
feature.write_csv()
print(feature.ip_total_length_for_every_packet())

parameter1:
    流所在的文件夹
parameter2:
    使用list[], 若想选用1，4，6，7特征，则对应[1，4，6，7]
parameter3:
    默认为5，此参数应用于第15特征，取每个流的前k个数据包的长度。
    若是取每个流前8个数据包的长度，则k=8

feature:
1.每个流数据包的数量
2.每个流最小数据包长度
3.每个流最大数据包长度
4.每个流数据包长度中位数
5.每个流数据包长度均值
6.每个流数据包长度方差
7.每个流中客户端发送数据包的数量
8.每个流中服务器发送数据包的数量
9.每个流中客户端发包数与服务器发包数的比值
10.每个流中包与包之间最小时间间隔
11.每个流中包与包之间最大时间间隔
12.每个流中包与包之间时间间隔均值
13.客户端数据包中ack!=0 数量
14.服务器数据包中ack!=0 数量
15.每个流中前k个数据包长度

scapy使用说明：
        flow = scapy.all.rdpcap(os.path.join(dirpath, file))
        此时flow是一个list，原码中多个flow组成Flows，Flows也是个list。
    故可用Flow[i][j]来访问每个数据包。
        example：
        访问第3个流中第2个数据包中的源端口
        Flow[2][1].sport
numpy使用说明：
    除15特征返回[self.flows_num, k]的矩阵，其余各个特征计算函数返回的
    shape为(self.flow_num)(1维), 为保证拼接：
    packet_num = np.expand_dims(packet_num, axis=1)
    执行此语句后shape变为[self.flows_num, 1](2维)
    而最初feature矩阵shape为[self.flows_num, 1]
    由此便可执行水平拼接操作：
    feature = np.hstack((feature, packet_num))
