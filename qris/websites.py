
try:
    from DFA import *
except:
    from .DFA import *

SITE_FEATURES = {
    'google':    {'base': ['www.google.com',      2,   False, True,  False, True,  'cp', 0,  0, range(0)], 'ss': range(173, 176), 'gs': True},
    'tmall':     {'base': ['suggest.taobao.com',  2,   False, True,  True,  True,  '',   10, 2, range(1, 4)]},
    'facebook':  {'base': ['www.facebook.com',    1.1, False, True,  False, False, '',   1,  1, range(5, 12)], 'cf': 2, 'fs': True},
    'baidu':     {'base': ['www.baidu.com',       1.1, False, True,  False, True,  'cp', 1,  0, range(0)], 'pwd': True, 'bd': True},
    'yahoo':     {'base': ['search.yahoo.com',    2,   True,  True,  False, True,  'c1', 1,  0, range(0)], 'ss': range(178, 179)},
    'wikipedia': {'base': ['www.wikipedia.org',   2,   True,  True,  False, True,  'c0', 0,  1, range(1, 5)]},
    'csdn':      {'base': ['sp0.baidu.com',       1.1, False, True,  False, True,  '',   4,  0, range(0)], 'cf': 2},
    'twitch':    {'base': ['gql.twitch.tv',       1.1, False, False, False, False, '',   32, 0, range(0)]},
    'bing':      {'base': ['www.bing.com',        2,   False, True,  False, True,  'cp', 0,  0, range(0)], 'th': 125}
}


class Website:
    '''
    Website features and functions.
    '''
    def __init__(self, website):
        if website not in SITE_FEATURES.keys():
            raise Exception('Currently supported websites: %s.' % ', '.join(SITE_FEATURES.keys()))
        
        self.website = website
        features = SITE_FEATURES[website]

        # Basic features
        self.server_name = features['base'][0]
        self.http_version = features['base'][1]
        self.index_header = features['base'][2]
        self.encode_space = features['base'][3]
        self.trim_space = features['base'][4]
        self.encode_apost = features['base'][5]
        self.counter = features['base'][6]
        self.change_byte = features['base'][7]
        self.add_byte = features['base'][8]
        self.ab_range = features['base'][9]
        
        # Special features
        if 'th' in features:
            self.threshold = features['th']
        if 'ss' in features:
            self.stretch = features['ss']
        if 'gs' in features:
            self.gs_mss = features['gs']
        if 'pwd' in features:
            self.pwd = features['pwd']
        if 'bd' in features:
            self.bdsvrtm = features['bd']
        if 'cf' in features:
            self.cancel = features['cf']
        if 'fs' in features:
            self.fakespace = features['fs']

        # Check features
        if self.http_version != 1.1 and self.http_version != 2:
            raise Exception('HTTP version not supported')
        if self.counter == '':
            self.ct_type = 'no'
            self.ct_start = 0
        elif self.counter == 'cp':
            self.ct_type = 'cp'
            self.ct_start = 1
        elif self.counter[0] == 'c' and self.counter[1:].isdigit():
            self.ct_type = 'cn'
            self.ct_start = int(self.counter[1:])
        else:
            raise Exception('Counter should be \'cp\' or \'cn\' (n = natural number)')
        self.ct_conflicts = [10, 20, 40, 50]
        if self.http_version == 2 and self.change_byte >= 16:
            raise Exception('HTTP/2 changing byte number should be less than 16')
        if self.http_version == 1.1 and self.add_byte >= 2:
            raise Exception('HTTP/1.1 added bytes number should be less than 2')
        if self.http_version == 2 and self.add_byte >= 3:
            raise Exception('HTTP/2 added bytes number should be less than 3')

    def __repr__(self):
        return self.website


    def DFA_transfer(self, dsize, state, zh, enc):
        '''
        DFA accepts query size difference.
        '''
        if self.http_version == 1.1:
            if zh:
                return H1_ZH_DFA_TF(dsize, state, enc)
            else:
                return H1_EN_DFA_TF(dsize, state, enc)
        else:
            if zh:
                return H2_ZH_DFA_TF(dsize, state, enc)
            else:
                return H2_EN_DFA_TF(dsize, state, enc)


    def _adjust_h1cp(self, dsize, state, ct, zh, enc):
        '''
        "cp" (cursor position) parameter.
        '''
        # Byte length +1
        if ct == 8:
            # (*) -> D, for Pinyin with delimiters
            if dsize == H1_ZH_DFA.L_D.value + 1 and zh and not enc:
                dsize = dsize - 1
            # (*) -> Dp, for Pinyin with percent-encoded delimiters
            if dsize == H1_ZH_DFA.L_Dp.value + 1 and zh and enc:
                dsize = dsize - 1
        elif ct == 9:
            # (*) -> L
            if dsize == H1_EN_DFA.L_L.value + 1:
                dsize = dsize - 1
            # L -> Dp, for English with percent-encoded delimiters
            if dsize == H1_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # (*) -> D, for Pinyin with delimiters
            if dsize == H1_ZH_DFA.L_D.value + 1 and zh and not enc:
                dsize = dsize - 1
            # (*) -> Dp, for Pinyin with percent-encoded delimiters
            if dsize == H1_ZH_DFA.L_Dp.value + 1 and zh and enc:
                dsize = dsize - 1

        return dsize, state
        

    def _adjust_h2cp(self, dsize, state, ct, zh, enc):
        '''
        Huffman-encoded "cp" (cursor position) parameter.
        Bit length changes when cp
        * from 8/9 to 10/11 (bit length +4)
        * units digit from 1/2 to 3/4 (bit length +1)
        * units digit from 8/9 to 0/1 (bit length -1, except 29 to 30)
        Assume the "cp" is less than 50.
        Conflicts happen when the counter
        * reach 10 (bit length +4)
        * reach 20 and 40 (bit length -1)
        Temporarily take the 1st conflict to be a delimiter
            and the 2nd to be a letter.
        No conflicts for Pinyin with percent-encoded delimiters.
        '''
        # bit length +1
        if ct % 10 == 1:
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1
        elif ct % 10 == 2:
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1

        # bit length +4
        if ct == 8:
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1
        elif ct == 9:
            # (*) -> L, the conflict is not for Pinyin with percent-encoded delimiters
            if dsize == H2_ZH_DFA.L_L.value + 1 and zh and enc:
                dsize = dsize - 1
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # Dp -> L, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.Dp_L.value + 1 and state == H2_EN_DFA.Dp.value and enc:
                dsize = dsize - 1
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1

        # Accept consecutive delimiters for conflicts
        if ct == 10:
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value and state == H2_EN_DFA.Dp.value and enc:
                state = H2_EN_DFA.L.value

        return dsize, state


    def _adjust_h1cn(self, dsize, state, ct, zh, enc):
        '''
        "cn" (counter from n) parameter.
        '''
        # Byte length +1
        if ct == 9:
            # (*) -> L
            if dsize == H1_EN_DFA.L_L.value + 1:
                dsize = dsize - 1
            # L -> Dp, for English with percent-encoded delimiters
            if dsize == H1_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # (*) -> D, for Pinyin with delimiters
            if dsize == H1_ZH_DFA.L_D.value + 1 and zh and not enc:
                dsize = dsize - 1
            # (*) -> Dp, for Pinyin with percent-encoded delimiters
            if dsize == H1_ZH_DFA.L_Dp.value + 1 and zh and enc:
                dsize = dsize - 1

        return dsize, state

    
    def _adjust_h2cn(self, dsize, state, ct, zh, enc):
        '''
        Huffman-encoded "cn" (counter from n) parameter.
        Bit length changes when the counter
        * from 9 to 10 (bit length +4)
        * units digit from 2 to 3 (bit length +1)
        * units digit from 9 to 0 (bit length -1, except 29 to 30)
        Assume the counter is lass than 40.
        Conflicts happen when the counter
        * reach 10 (bit length +4)
        * reach 20 (bit length -1)
        Temporarily take the 1st conflict to be a delimiter
            and the 2nd to be a letter.
        No conflicts for Pinyin with percent-encoded delimiters.
        '''
        # bit length +1
        if ct % 10 == 2:
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1

        # bit length +4
        if ct == 9:
            # (*) -> L, no conflict for Pinyin with percent-encoded delimiters
            if dsize == H2_ZH_DFA.L_L.value + 1 and zh and enc:
                dsize = dsize - 1
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value + 1 and not zh and enc:
                dsize = dsize - 1
            # Dp -> L, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.Dp_L.value + 1 and state == H2_EN_DFA.Dp.value and enc:
                dsize = dsize - 1
            # (*) -> Dx, for Pinyin with percent-encoded delimiters
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh and enc:
                dsize = dsize - 1

        # Accept consecutive delimiters for conflicts
        if ct == 10:
            # (*) -> Dp, for English with percent-encoded delimiters
            if dsize == H2_EN_DFA.L_Dp.value and state == H2_EN_DFA.Dp.value and enc:
                state = H2_EN_DFA.L.value

        return dsize, state


    def adjust_ct(self, dsize, state, ct, zh, enc):
        '''
        Counter parameter.
        '''
        if self.ct_type == 'cp':
            if self.http_version == 1.1:
                dsize, state = self._adjust_h1cp(dsize, state, ct, zh, enc)
            else:
                dsize, state = self._adjust_h2cp(dsize, state, ct, zh, enc)
        elif self.ct_type == 'cn':
            if self.http_version == 1.1:
                dsize, state = self._adjust_h1cn(dsize, state, ct, zh, enc)
            else:
                dsize, state = self._adjust_h2cn(dsize, state, ct, zh, enc)
        
        return dsize, state


    def check_ct(self, dsize, state, ct):
        '''
        Check the conflict caused by Huffman-encoded counter parameter.
        '''
        if self.http_version == 2:
            if (('Apo' in state) or ('Spa' in state)):
                if dsize == H2_EN_DFA.L_L.value + 1 and ct < 20:
                    return True
            else:
                if dsize == H2_EN_DFA.L_L.value and ct >= 20:
                    return True
        
        return False


    def _strip_h1ab(self, dsize, state, idx, ab, zh, enc):
        '''
        Added bytes.
        Assume added bytes number is less than 2.
        The conflict happens when added bytes upon a letter
            for Chinese without percent-encoded delimiters.
        Temporarily take the conflict to be a delimiter.
        '''
        if self.add_byte in range(1, 2):
            if idx in self.ab_range:
                # Add a byte upon a letter
                if dsize == H1_EN_DFA.L_L.value + 1 and enc:
                    dsize = H1_EN_DFA.L_L.value
                    ab = 1
                # Add a byte upon a percent-encoded delimiter
                if dsize == H1_EN_DFA.L_Dp.value + 1 and not zh and enc:
                    dsize = H1_EN_DFA.L_Dp.value
                    ab = 1
                # Add a byte upon a delimiter
                if dsize == H1_ZH_DFA.L_D.value + 1 and zh and not enc:
                    dsize = H1_ZH_DFA.L_D.value
                    ab = 1
                # Add a byte upon a percent-encoded delimiter
                if dsize == H1_ZH_DFA.L_Dp.value + 1 and zh and not enc:
                    dsize = H1_ZH_DFA.L_Dp.value
                    ab = 1
        
        return dsize, state, ab

    
    def _strip_h2ab(self, dsize, state, idx, ab, zh, enc):
        '''
        Huffman-encoded added bytes.
        Assume added bytes number is less than 3.
        The conflict happens when adding bytes upon a letter.
        Temporarily take the conflict to be a delimiter.
        '''
        if self.add_byte in range(1, 3):
            if idx in self.ab_range:
                # Add byte(s) upon a delimiter
                if dsize in [x + 2 for x in H2_ZH_DFA.L_Dx.value] and zh:
                    dsize = max(H2_ZH_DFA.L_Dx.value)
                    ab = 1
                # Add byte(s) upon a percent-encoded delimiter
                if dsize in [H2_EN_DFA.L_Dp.value + x for x in (1, 2)] and not zh and enc:
                    dsize = H2_EN_DFA.L_Dp.value
                    ab = 1

            # Accept consecutive delimiters for conflicts
            if idx in [i + 1 for i in self.ab_range]:
                # (*) -> Dp, for English with percent-encoded delimiters
                if dsize == H2_EN_DFA.L_Dp.value and state == H2_EN_DFA.Dp.value:
                    state = H2_EN_DFA.L.value
        
        return dsize, state, ab


    def strip_ab(self, dsize, state, idx, ab, zh, enc):
        '''
        Adjust added bytes.
        '''
        # Added already
        if ab == 1:
            ab = 0
        else:
            if self.http_version == 1.1:
                dsize, state, ab = self._strip_h1ab(dsize, state, idx, ab, zh, enc)
            else:
                dsize, state, ab = self._strip_h2ab(dsize, state, idx, ab, zh, enc)
            
        return dsize, state, ab

    
    def _check_h1ab(self, dsize, state):
        '''
        Conflicts for Chinese without percent-encoded delimiters.
        Assume added bytes number is lass than 2.
        '''
        if self.add_byte in range(1, 2):
            if (('Apo' in state) or ('Spa' in state)):
                if dsize == H1_EN_DFA.L_L.value + 1:
                    return True
        
        return False

    
    def _check_h2ab(self, dsize, state):
        '''
        Conflicts upon letters.
        Assume added bytes number is lass than 3.
        '''
        if self.add_byte in range(1, 3):
            if (('Apo' in state) or ('Spa' in state)):
                if self.add_byte == 1:
                    if dsize == H2_EN_DFA.L_L.value + 1:
                        return True
                elif self.add_byte == 2:
                    if dsize in [H2_EN_DFA.L_L.value + x for x in (1, 2)]:
                        return True
        
        return False


    def check_ab(self, dsize, state):
        '''
        Check the conflict caused by added bytes.
        '''
        if self.http_version == 1.1:
            return self._check_h1ab(dsize, state)
        else:
            return self._check_h2ab(dsize, state)


    def adjust_cb(self, dsize, state, zh):
        '''
        Huffman-encoded changing byte parameter.
        '''
        if self.http_version == 2 and self.change_byte > 0:
            if self.change_byte > 1:
                # Size decrease upon letters
                if dsize == H2_EN_DFA.L_L0.value - 1:
                    dsize = H2_EN_DFA.L_L0.value
                if dsize == H2_EN_DFA.L_L0.value and state == H2_EN_DFA.L0.value:
                    dsize = H2_EN_DFA.L_L.value
            # Size increase upon delimiters
            if dsize == H2_EN_DFA.L_Dp.value + 1 and not zh:
                dsize = H2_EN_DFA.L_Dp.value
            if dsize == max(H2_ZH_DFA.L_Dx.value) + 1 and zh:
                dsize = max(H2_ZH_DFA.L_Dx.value)
        
        return dsize


    def check_cb(self, dsize):
        '''
        Check the conflict caused by Huffman-encoded changing byte parameters.
        '''
        if self.http_version == 2 and self.change_byte > 1:
            if dsize == H2_EN_DFA.L_L.value + 1:
                return True
        
        return False


    def check_gs(self, dsize, Lsize, gsmss):
        '''
        Google's special "gs_mss" parameter.
        Huffman-encoded gs_mss parameter prefix size (5 or 6)
        plus the first letter size (+1)
        '''
        # Huffman-encoded gs_mss prefix (5 or 6) + first letter (+1)
        gs_size = 6
        # All possible transfer size
        accept_sizes = range(H2_EN_DFA.L_L0.value - 1, max(H2_ZH_DFA.L_Dx.value) + 3)

        next_state = H2_EN_DFA.NUL.value

        if len(Lsize) > 1:
            inc = Lsize[-1] - Lsize[0]

            # gs_mss parameter added
            if gsmss == 0:
                if dsize - inc - gs_size in accept_sizes:
                    next_state = H2_EN_DFA.L.value
                    gsmss = inc

            # gs_mss parameter removed
            else:
                if dsize + gsmss + gs_size in accept_sizes:
                    next_state = H2_EN_DFA.L.value
                    gsmss = 0

        return next_state, gsmss


    def strip_pwd(self, dsize, state, ct):
        '''
        Baidu's special "pwd" (past word) parameter.
        '''
        if hasattr(self, 'pwd'):
            # minus name "&pwd="
            if ct == 1:
                dsize = dsize - 5

            # minus length change
            if state == H1_EN_DFA.L.value:
                # (*) -> L
                dsize = dsize - H1_EN_DFA.L_L.value

            elif state == H1_EN_DFA.Dp.value:
                # L -> Dp
                dsize = dsize - H1_EN_DFA.L_Dp.value

            elif state == H1_ZH_DFA.D.value:
                # (*) -> D
                dsize = dsize - H1_ZH_DFA.L_D.value

            elif state == H1_ZH_DFA.Dp.value:
                # (*) -> Dp
                dsize = dsize - H1_ZH_DFA.L_Dp.value
        
        return dsize


    def check_bd(self, dsize, state, ct, coochg, idx, char, zh, enc):
        '''
        Baidu's special Cookie change.
        Cookie size may change ONCE at the 3rd request in two different ways:
            * BDSVRTM Cookie is added when in a refreshed the webpage
            * BD_CK_SAM, PSINO, DelPer and BDSVRTM Cookies are added and
              H_PS_PSSID Cookie size changes in a newly opened browser
        After the 3rd request, Cookie size may float occasionally due to:
            * H_PS_PSSID Cookie size may +/- 5 bytes
            * BDSVRTM Cookie size may +/- 1 byte
        '''
        BDSVRTM = 12
        delPer = 10
        BD_CK_SAM = 13
        PSINO = 9
        add_full = BDSVRTM + delPer + BD_CK_SAM + PSINO
        add_range = range(BDSVRTM, add_full + 40)

        H_PS_PSSID = 5
        BDSVRTM = 1
        float_sizes = (H_PS_PSSID, -H_PS_PSSID, BDSVRTM, -BDSVRTM)
        float_sizes += (H_PS_PSSID+BDSVRTM, -H_PS_PSSID-BDSVRTM)
        float_sizes += (H_PS_PSSID-BDSVRTM, -H_PS_PSSID+BDSVRTM)
        
        next_state = H1_EN_DFA.NUL.value
        dsize = self.strip_pwd(dsize, state, ct)

        # Cookie added
        if coochg == 0:
            if idx >= 2 and dsize in add_range:
                if char:
                    next_state = H1_EN_DFA.L.value
                elif not zh and enc:
                    next_state = H1_EN_DFA.Dp.value
                elif zh and not enc:
                    next_state = H1_ZH_DFA.D.value
                elif zh and enc:
                    next_state = H1_ZH_DFA.Dp.value
                coochg = dsize

        # Cookie changed
        else:
            for change in float_sizes:
                _dsize, _state = self.adjust_ct(dsize - change, state, ct, zh, enc)
                next_state = self.DFA_transfer(_dsize, _state, zh, enc)

                if next_state != H1_EN_DFA.NUL.value:
                    coochg += change
                    break

        return next_state, coochg
