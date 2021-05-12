import dpkt
import socket
import struct
import numpy as np
import pandas as pd

try:
    from websites import Website, SITE_FEATURES
except:
    from .websites import Website, SITE_FEATURES

import random
random.seed()

class Packets:
    '''
    Packets in network traffic.
    '''
    def __init__(self, pcap, website):
        self.__reader = self.__pcap_reader(pcap)

        if website is None:
            website = self._detect_website(pcap)
        self.website = Website(website)

        tuples = self._filter_conv(pcap)
        self.packets = self._load_pcap(pcap, tuples)
		
        ####################################################
        # Mitigation: Padding (require CB > 1)
        # for i, _ in self.packets.iterrows():
        #     # Increase 1 byte with probability 0.5
        #     if random.random() < 0.5:
        #         self.packets.loc[i, 'size'] += 1
        ####################################################
        # Mitigation: Dummy traffic
        # packets = self.packets.copy()
        # _packets = pd.DataFrame(columns = packets.columns)
        # for _, row in self.packets.iterrows():
        #     _packets = _packets.append(row)
        #     # Duplicate 10% packets (+50ms)
        #     if random.random() < 0.1:
        #         _packets = _packets.append(row)
        #         _packets.iloc[-1, 0] += 50
        # _packets = _packets.sort_values('time')
        # self.packets = _packets.reset_index(drop=True)
        ####################################################
        # Mitigation: Network noise
        # packets = self.packets.copy()
        # for i, _ in self.packets.iterrows():
        #     # Laplace deviation with scale 32ms
        #     deviation = np.random.laplace(scale=32)
        #     packets.loc[i, 'time'] += deviation
        # packets = packets.sort_values('time')
        # self.packets = packets.reset_index(drop=True)
        ####################################################

        self.keystrokes = []

    def __repr__(self):
        return self.packets

    def __pcap_reader(self, pcap):
        try:
            dpkt.pcap.Reader(open(pcap, 'rb'))
            reader = dpkt.pcap
        except:
            dpkt.pcapng.Reader(open(pcap, 'rb'))
            reader = dpkt.pcapng

        return reader


    def _detect_website(self, pcap):
        '''
        Detect website according to TLS server name.
        '''
        with open(pcap, 'rb') as fpcap:
            for _, buf in self.__reader.Reader(fpcap):
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP and \
                    eth.type != dpkt.ethernet.ETH_TYPE_IP6:
                    continue

                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                
                tcp = ip.data
                # HTTPS
                if tcp.dport != 443:
                    continue

                if len(tcp.data) < 6:
                    continue

                # TLS client hello
                if tcp.data[0] == 22 and tcp.data[5] == 1:
                    for website in SITE_FEATURES:
                        if SITE_FEATURES[website]['base'][0].encode() in tcp.data:
                            return website

        raise Exception('No supported server name in packets')


    def _filter_conv(self, pcap):
        '''
        Filter IP conversation according to TLS server name.
        '''
        tuples = []
        with open(pcap, 'rb') as fpcap:
            for _, buf in self.__reader.Reader(fpcap):
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP and \
                    eth.type != dpkt.ethernet.ETH_TYPE_IP6:
                    continue

                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                
                tcp = ip.data
                # HTTPS
                if tcp.dport != 443:
                    continue

                if len(tcp.data) < 6:
                    continue

                if tcp.data[0] == 22 and \
                    tcp.data[5] == 1:
                    if self.website.server_name.encode() in tcp.data:
                        tuples.append((ip.src, ip.dst))

        if len(tuples) > 0:
            tuples = list(set(tuples))
        else:
            raise Exception('Cannot filter conversation by server name')

        return tuples


    def _load_pcap(self, pcap, tuples):
        '''
        Load a pcap(ng) into a pandas DataFrame.
        Filter IP conversion by tuples if provided.
        Filter data packets sent to HTTPS servers.
        Remove TCP retransmission and disorder packets.
        '''
        packets = []
        first_ts = 0
        port_seq = {}
        with open(pcap, 'rb') as fpcap:
            for ts, buf in self.__reader.Reader(fpcap):
                if first_ts == 0:
                    first_ts = ts
                time = (ts - first_ts) * 1000

                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    family = socket.AF_INET
                elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                    family = socket.AF_INET6
                else:
                    continue
                
                ip = eth.data
                if ip.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                if len(tuples) > 0:
                    if (ip.src, ip.dst) not in tuples:
                        continue
                src = socket.inet_ntop(family, ip.src)
                dst = socket.inet_ntop(family, ip.dst)
                
                tcp = ip.data
                # HTTPS
                if tcp.dport != 443:
                    continue
                if len(tcp.data) == 0:
                    continue
                # TLS application data
                if tcp.data[0] != 23:
                    continue
                sport = tcp.sport
                if sport in port_seq:
                    if tcp.seq <= port_seq[sport]:
                        continue
                    else:
                        port_seq[sport] = tcp.seq
                else:
                    port_seq[sport] = tcp.seq

                # Use TLS length instead of TCP length to avoid segmentation
                size = struct.unpack(">h", tcp.data[3:5])[0]
                
                packets.append((time, src, dst, sport, size))

        return pd.DataFrame(packets, columns=['time', 'src', 'dst', 'sport', 'size'])

    
    def _longest_accepted_subsequence(self, L_size, L_time):
        '''
        Find the longest accepted subsequence (LAS).
        '''
        def __dl_copy(dl1, dl2):
            '''
            Dict list copy.
            '''
            for k in dl2:
                dl1[k] = dl2[k].copy()

        def __dl_append(dl, d):
            '''
            Dict list append.
            '''
            for k in d:
                dl[k].append(d[k])

        zh = self.__zh
        enc = self.__enc
        
        n = len(L_size)
        LDL = [{
            'time': [], 'size': [], 'idx': [], 'state': [],
            'ct': [], 'ab': [], 'gsmss': [], 'coochg': []
            } for _ in range(n)]

        for i in range(n):
            # Initial state
            state = 'Ltr'
            ct = self.website.ct_start
            if self.website.index_header:
                ct += 1
            ab = 0
            gsmss = 0
            coochg = 0

            ct_inc = 0
            for j in range(i)[::-1]:
                dtime = L_time[i] - LDL[j]['time'][-1]
                dsize = L_size[i] - LDL[j]['size'][-1]

                # Keystroke timing inverval > 20ms
                if dtime <= 20:
                    # Duplicated request makes counter +1
                    if self.website.ct_type == 'cn':
                        ct_inc = 1
                    continue

                # Current state
                idx = len(LDL[j]['idx'])
                if self.website.index_header:
                    idx += 1
                _state = LDL[j]['state'][-1]
                _ct = LDL[j]['ct'][-1] + ct_inc
                _ab = sum(LDL[j]['ab'])
                _gsmss = LDL[j]['gsmss'][-1]
                _coochg = LDL[j]['coochg'][-1]

                # Keystroke timing interval < 1s
                if dtime >= 1000:
                    break

                # Adjust pwd (past word) parameter
                _dsize = self.website.strip_pwd(dsize, _state, _ct)

                # Adjust added bytes
                _dsize, __state, _ab = self.website.strip_ab(_dsize, _state, idx, _ab, zh, enc)
                
                # Adjust counter parameter
                _dsize, __state = self.website.adjust_ct(_dsize, __state, _ct, zh, enc)

                # Adjust changing bytes
                _dsize = self.website.adjust_cb(_dsize, __state, zh)
                
                # Apply DFA transfer function
                next_state = self.website.DFA_transfer(_dsize, __state, zh, enc)

                # If not accepted, check special features
                if next_state == 'Nul':
                    # gs_mss parameter changed
                    if hasattr(self.website, 'gs_mss'):
                        next_state, _gsmss = self.website.check_gs(dsize, LDL[j]['size'], _gsmss)
                    
                    # BDSVRTM Cookie changed
                    if hasattr(self.website, 'bdsvrtm'):
                        next_state, _coochg = self.website.check_bd(dsize, _state, _ct, _coochg, idx, self.__char, zh, enc)

                # Update the longest prefix that accepts the next state
                if next_state != 'Nul' and len(LDL[j]['idx']) > len(LDL[i]['idx']):
                    state = next_state
                    if 'Apo' in state and self.website.ct_type == 'cp':
                        ct = _ct + 2
                    else:
                        ct = _ct + 1
                    ab = _ab
                    gsmss = _gsmss
                    coochg = _coochg
                    __dl_copy(LDL[i], LDL[j])
            
            # Longest subsequence ending in packet i
            __dl_append(LDL[i], {
                'time': L_time[i], 'size': L_size[i], 'idx': i, 'state': state,
                'ct': ct, 'ab': ab, 'gsmss': gsmss, 'coochg': coochg})

        longest = 0
        for i in range(n):
            # Keystroke number > 2
            if len(LDL[i]['idx']) <= 2:
                continue

            # Average keystroke timing interval > 50 ms
            if np.diff([L_time[i] for i in LDL[i]['idx']]).mean() <= 50:
                continue
            
            # Check identical size sequence
            if self.website.change_byte > 0:
                if np.median(LDL[i]['size']) == LDL[i]['size'][-1]:
                    continue
            
            # Check the last fake gs_mss parameter
            if hasattr(self.website, 'gs_mss'):
                if LDL[i]['gsmss'][-1] > 0 and LDL[i]['gsmss'][-2] == 0:
                    gap = LDL[i]['idx'][-1] - LDL[i]['idx'][-2]
                    for j in range(len(LDL[i]['gsmss'])-2):
                        if (LDL[i]['idx'][j+1] - LDL[i]['idx'][j]) * 2 >= gap:
                            gap = 0
                            break
                    if gap:
                        LDL[i]['idx'] = LDL[i]['idx'][:-1]
                        LDL[i]['state'] = LDL[i]['state'][:-1]

            if len(LDL[i]['idx']) > len(LDL[longest]['idx']):
                longest = i

        return LDL[longest]

    
    def _check_stream(self, stream):
        '''
        Recognize keystrokes in a network stream.
        '''
        def __dl_insert(dl, d):
            '''
            Dict list head insert.
            '''
            for k in d:
                dl[k] = [d[k]] + dl[k]

        L_size = stream['size'].values.tolist()
        L_time = stream['time'].values.tolist()

        # Remove small packets which may mislead the result
        if hasattr(self.website, 'threshold'):
            L_size = [0 if x < self.website.threshold else x for x in L_size]

        # Handle the special added Cookies
        if hasattr(self.website, 'bdsvrtm'):
            self.__char = True
            DL1 = self._longest_accepted_subsequence(L_size, L_time)
            self.__char = False
            DL2 = self._longest_accepted_subsequence(L_size, L_time)

            # Longer subsequence with fewer delimiters
            if len(DL1['idx']) > len(DL2['idx']):
                DL_longest = DL1.copy()
            elif len(DL1['idx']) < len(DL2['idx']):
                DL_longest = DL2.copy()
            else:
                deli_n1 = sum(('Spa' in x) or ('Apo' in x) for x in DL1['state'])
                deli_n2 = sum(('Spa' in x) or ('Apo' in x) for x in DL2['state'])
                if deli_n1 <= deli_n2:
                    DL_longest = DL1.copy()
                else:
                    DL_longest = DL2.copy()
        
        # Find the longest subsequence
        else:
            DL = self._longest_accepted_subsequence(L_size, L_time)
            DL_longest = DL.copy()
        
        # Remove the extra byte appended to the String Length field in HAPCK
        if hasattr(self.website, 'stretch'):
            longest = len(DL_longest['idx'])
            deli_min = sum(('Spa' in x) or ('Apo' in x) for x in DL_longest['state'])

            for stretch_size in self.website.stretch:
                # The gap size caused by the length byte can never exist
                if stretch_size in L_size:
                    continue

                _L_size = [x - 1 if x > stretch_size else x for x in L_size]
                DL = self._longest_accepted_subsequence(_L_size, L_time)

                # Longest subsequence with fewest delimiters
                if len(DL['idx']) > longest:
                    longest = len(DL['idx'])
                    deli_min = sum(('Spa' in x) or ('Apo' in x) for x in DL['state'])
                    DL_longest = DL.copy()
                    self.website._stretch_size = stretch_size

                elif len(DL['idx']) == longest:
                    deli_n = sum(('Spa' in x) or ('Apo' in x) for x in DL['state'])
                    if deli_n <= deli_min:
                        deli_min = deli_n
                        DL_longest = DL.copy()
                        self.website._stretch_size = stretch_size


        # Adjust unindexed headers
        if self.website.index_header:
            idx = DL_longest['idx']
            for i in range(idx[0])[::-1]:
                # Keystroke timing interval < 1s
                if L_time[idx[0]] - L_time[i] >= 1000:
                    break
                
                # Keystroke timing inverval > 20ms
                if L_time[idx[0]] - L_time[i] <= 20:
                    continue

                if L_size[i] > L_size[idx[0]]:
                    # Assume the second keystroke is character
                    __dl_insert(DL_longest, {
                        'time': L_time[i], 'size': L_size[i], 'idx': i, 'state': 'Ltr',
                        'ct': DL_longest['ct'][0] - 1, 'ab': 0, 'gsmss': 0, 'coochg': 0})
                    break
        
        # Record the longest subsequence and its matedata
        if len(DL_longest['idx']) > len(self.keystrokes):
            self.keystrokes = stream.iloc[DL_longest['idx']].copy()
            self.keystrokes['state'] = DL_longest['state']
            if self.website.ct_type != 'no':
                self.keystrokes['ct'] = DL_longest['ct']
            if self.website.add_byte > 0:
                self.keystrokes['ab'] = DL_longest['ab']
            if hasattr(self.website, 'gs_mss'):
                self.keystrokes['gsmss'] = DL_longest['gsmss']
            if hasattr(self.website, 'bdsvrtm'):
                self.keystrokes['coochg'] = DL_longest['coochg']
            if hasattr(self.website, '_stretch_size'):
                exclude = lambda x: x - 1 if x > self.website._stretch_size else x
                self.keystrokes['size'] = self.keystrokes['size'].apply(exclude)


    def _prepend_head(self, target):
        '''
        Append a keystroke to the head.
        '''
        keystrokes = target.copy()
        key = pd.DataFrame(columns = keystrokes.columns)
        key = key.append(keystrokes.loc[0, :])
        key['time'] = key['time'] - 1000
        key['size'] = key['size'] - 1
        if self.website.ct_type != 'no':
            key['ct'] = key['ct'] - 1
        keystrokes = key.append(keystrokes)
        keystrokes.reset_index(drop=True, inplace=True)
        return [keystrokes]

    
    def _discard_tail(self, target):
        '''
        Discard the keystroke at the tail.
        '''
        keystrokes = target.copy()
        valid = keystrokes.shape[0] - 2
        return [keystrokes.loc[:valid, :]]


    def _discard_dup_space(self, target):
        '''
        Discard duplicated Space keystrokes.
        '''
        keystrokes = target.copy()
        dup_spaces = target[target['state'].shift(-1).apply(lambda x: 'Spa' in str(x))].index.tolist()
        if dup_spaces[0] == 0:
            dup_spaces = [] if len(dup_spaces) == 1 else dup_spaces[1:]
        if len(dup_spaces) > 0:
            keystrokes.drop(dup_spaces, inplace=True)
            keystrokes.reset_index(drop=True, inplace=True)
        return [keystrokes]

    
    def _discard_dup_space_with_addbyte(self, target):
        '''
        Discard duplicated Space keystrokes with added bytes conflicts.
        '''
        L_keystrokes = []
        states = target['state']
        dsize = target['size'].diff().fillna(1).astype(int)
        for idx in self.website.ab_range:
            if len(dsize) < 2 or idx > dsize.index[-1]:
                break
            if self.website.check_ab(dsize[idx], state=states[idx]) == True:
                target.loc[idx, 'state'] = 'Ltr'
                target.loc[idx, 'ab'] = 1
                L_keystrokes += self._discard_dup_space(target)
                target.loc[idx, 'state'] = 'Spa(%)+Ltr'
                target.loc[idx, 'ab'] = 0
        return L_keystrokes


    def correlate_state(self, chinese, trident):
        '''
        Correlate keystroke packets with DFA query states.
        '''
        self.__zh = chinese
        if self.__zh:
            self.__enc = self.website.encode_apost
            if trident:
                self.__enc = False
        else:
            self.__enc = self.website.encode_space
            # English with Space trimmer can be treated as Chinese
            if self.website.trim_space:
                self.__zh = True

        # Yahoo duplicates requests when using Microsoft Pinyin IME
        if str(self.website) == 'yahoo' and chinese:
            self.website.index_header = False
            self.website.ct_start = 2

        # Find the longest subsequence
        if self.website.http_version == 1.1:
            for src, dst in self.packets[['src', 'dst']].drop_duplicates().values:
                stream = self.packets[(self.packets['src'] == src) & (self.packets['dst'] == dst)]
                self._check_stream(stream)
                
        elif self.website.http_version == 2:
            for src, sport, dst in self.packets[['src', 'sport', 'dst']].drop_duplicates().values:
                stream = self.packets[(self.packets['src'] == src) & (self.packets['sport'] == sport) & (self.packets['dst'] == dst)]
                self._check_stream(stream)
        
        if type(self.keystrokes) is list or len(self.keystrokes) < 2:
            raise Exception('No available subsequence found in packets')

        self.keystrokes.reset_index(drop=True, inplace=True)
        self.keystrokes.drop(['src', 'dst', 'sport'], axis=1, inplace=True)
        self.keystrokes = [self.keystrokes]
        
        # Handle cancel of the first request(s)
        if hasattr(self.website, 'cancel'):
            for i in range(self.website.cancel):
                self.keystrokes += self._prepend_head(self.keystrokes[i])

        # Handle conflict of the last candidate request in Chinese
        if chinese and len(self.keystrokes[0]) > 2:
            for i in range(len(self.keystrokes)):
                self.keystrokes += self._discard_tail(self.keystrokes[i])

        # Handle English with Space trimmer
        if not chinese and self.website.trim_space:
            for i in range(len(self.keystrokes)):
                if sum(('Apo' in x) for x in self.keystrokes[i]['state']) > 0:
                    self.keystrokes[i]['state'].replace(r'Apo.*', 'Spa(%)+Ltr', regex=True, inplace=True)
                    self.keystrokes += self._discard_dup_space(self.keystrokes[i])

                    # Handle conflicts caused by added bytes
                    if self.website.add_byte > 0 and sum(self.keystrokes[i]['ab']) == 0:
                        self.keystrokes += self._discard_dup_space_with_addbyte(self.keystrokes[i])

        return self.keystrokes


    def delimit_token(self, chinese):
        '''
        Delimit keystrokes into tokens according to their states.
        '''
        for keystrokes in self.keystrokes:
            states = keystrokes['state']
            dsize = keystrokes['size'].diff().fillna(1).astype(int)

            # Label delimiters to group keystrokes
            if chinese:
                delimiters = states.apply(lambda x: 1 if 'Apo' in x else 0)
            else:
                delimiters = states.apply(lambda x: 1 if 'Spa' in x else 0)

            # English without percent-encoded Space cannot be delimited
            if not chinese and not self.website.encode_space:
                delimiters[:] = -1

            # Tag conflicts caused by unindexed headers
            if self.website.index_header and dsize[1] < 0:
                delimiters[1] = -1

            # Tag conflicts caused by canceled requests
            if hasattr(self.website, 'cancel'):
                dtime = keystrokes['time'].diff().fillna(0)
                delimiters[dtime == 1000] = -1
            
            # Tag conflicts caused by counter parameter
            if self.website.ct_type != 'no':
                for conflict in self.website.ct_conflicts:
                    increase = keystrokes[keystrokes['ct'] >= conflict]
                    if increase.empty:
                        continue
                    idx = increase.index[0]
                    ct = increase.iloc[0]['ct']
                    if self.website.check_ct(dsize[idx], state=states[idx], ct=ct) == True:
                        delimiters[idx] = -1
            
            # Tag conflicts caused by added bytes
            if self.website.add_byte > 0 and sum(keystrokes['ab']) == 0:
                for idx in self.website.ab_range:
                    if len(dsize) < 2 or idx > dsize.index[-1]:
                        break
                    if self.website.check_ab(dsize[idx], state=states[idx]) == True:
                        delimiters[idx] = -1
                        keystrokes.loc[idx, 'ab'] = 1
            
            # Tag conflicts caused by changing bytes
            conflicts = dsize.apply(self.website.check_cb)
            delimiters[conflicts] = -1

            # Tag conflicts caused by gs_mss parameter
            if hasattr(self.website, 'gs_mss'):
                delimiters[abs(dsize) > 4] = -1

            # Tag fake Space
            if hasattr(self.website, 'fakespace'):
                if delimiters[1] == 1:
                    delimiters[1] = -1

            keystrokes['delimiter'] = delimiters

        return self.keystrokes


    def size_pattern(self):
        '''
        Get the size increasing pattern of compressed query.
        Only for HTTP/2 with HPACK compression.
        '''
        if self.website.http_version == 2:
            for keystrokes in self.keystrokes:
                pattern = keystrokes['size'].diff().fillna(1).astype(int)

                # Tag delimiter conflicts
                pattern[keystrokes['delimiter'] == -1] = -1

                # Tag conflicts caused by added bytes
                if self.website.add_byte > 0:
                    pattern[self.website.ab_range] = -1

                # Tag conflicts caused by extra length byte
                if hasattr(self.website, '_stretch_size'):
                    keystrokes['lsize'] = keystrokes['size'].shift().fillna(0).astype(int)
                    stretch = self.website._stretch_size
                    conflicts = keystrokes[(keystrokes['lsize'] < stretch) & (keystrokes['size'] >= stretch)]
                    pattern[conflicts.index] = -1
                    del keystrokes['lsize']

                keystrokes['pattern'] = pattern

        return self.keystrokes

    
    def timing_interval(self):
        '''
        Get keystroke timing intervals within tokens.
        '''
        for keystrokes in self.keystrokes:
            intervals = keystrokes['time'].diff().fillna(0)

            # Keep only intra-token timing intervals
            intervals[keystrokes['delimiter'] == 1] = 0

            keystrokes['interval'] = intervals

        return self.keystrokes
