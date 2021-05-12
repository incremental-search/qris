import os
import pickle
import numpy as np
import pandas as pd
import pkg_resources
import xpinyin
py = xpinyin.Pinyin()

from tqdm import tqdm
from scipy import stats
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH

try:
    from websites import Website
except:
    from .websites import Website

MODEL_PATH = pkg_resources.resource_filename('qris', 'models/')
def_dic_en = os.path.join(MODEL_PATH, 'queries_AOL.csv')
def_dic_zh = os.path.join(MODEL_PATH, 'queries_THU.csv')
def_bigrams = os.path.join(MODEL_PATH, 'bigrams.csv')


class Queries:
    '''
    Queries of prediction target set.
    '''
    def __init__(self, website, chinese=False, dic=None, bigrams=None, verbose=False):
        if type(website) is str:
            self.website = Website(website)
        else:
            self.website = website

        if dic is not None:
            self.queries = self._load_queries(dic)
        else:
            if chinese:
                self.queries = self._load_queries(def_dic_zh)
            else:
                self.queries = self._load_queries(def_dic_en)

        if bigrams is not None:
            self.bigrams = self._load_bigrams(bigrams)
        else:
            self.bigrams = self._load_bigrams(def_bigrams)

        self.chinese = chinese

        # Preload to accelerate evaluation
        self.length = self._load_length(verbose)
        self.tokens = self._load_token(verbose)
        self.patterns = self._load_pattern(verbose)
        self.rhythms = self._load_rhythm(verbose)

        self.candidates = []
        self.candidate_idx = []

    def __repr__(self):
        return self.queries


    def __load_matedata(self, fname):
        fpath = os.path.join(MODEL_PATH, fname)
        if not os.path.exists(fpath):
            print('Cannot find', fname)
            print('Preloading for the first time...')
            return

        with open(fpath, 'rb') as f:
            data = pickle.load(f)
            if len(data) != len(self.queries):
                print('Cannot match query set scale')
                print('Reloading for the first time...')
                return
            return data


    def __save_matedata(self, obj, fname):
        fname = os.path.join(MODEL_PATH, fname)
        with open(fname, 'wb') as f:
            pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


    def _load_queries(self, dic):
        '''
        Load queries.
        '''
        queries = pd.read_csv(dic, names=['query'])
        queries = queries.squeeze()
        queries = queries.drop_duplicates()

        return pd.DataFrame(queries)

    
    def _load_bigrams(self, bigrams):
        '''
        Load bigrams.
        '''
        return pd.read_csv(bigrams, index_col=[0, 1])


    def _load_length(self, verbose):
        '''
        Get query length.
        '''
        if verbose:
            print('Loading query length')
        if self.chinese:
            length = self.__load_matedata('length_zh.pkl')
            if length is None:
                tqdm.pandas(desc='pinyin')
                length = self.queries['query'].progress_apply(lambda x: py.get_pinyin(x, '')).str.len()
                self.__save_matedata(length, 'length_zh.pkl')
        else:
            if self.website.trim_space:
                length = self.__load_matedata('length_en_trim.pkl')
            else:
                length = self.__load_matedata('length_en.pkl')
            if length is None:
                if self.website.trim_space:
                    length = self.queries['query'].str.replace(' ', '').str.len()
                    self.__save_matedata(length, 'length_en_trim.pkl')
                else:
                    length = self.queries['query'].str.len()
                    self.__save_matedata(length, 'length_en.pkl')
        
        return length


    def _load_token(self, verbose):
        '''
        Get query token length.
        '''
        def __get_sequence(tokens):
            '''
            Get delimiter sequence.
            '''
            sequence = [0 for c in tokens[0]]
            for i in range(len(tokens) - 1):
                sequence += [1] + [0 for c in tokens[i+1]]

                if self.chinese or self.website.trim_space:
                    sequence = sequence[:-1]

            return sequence

        if verbose:
            print('Loading query tokens')
        if self.chinese:
            tokens = self.__load_matedata('token_zh.pkl')
            if tokens is None:
                tqdm.pandas(desc='pinyin')
                tokens = self.queries['query'].progress_apply(lambda x: py.get_pinyin(x).split('-'))
                tqdm.pandas(desc='tokens')
                tokens = tokens.progress_apply(__get_sequence)
                self.__save_matedata(tokens, 'token_zh.pkl')
        else:
            if self.website.trim_space:
                tokens = self.__load_matedata('token_en_trim.pkl')
            else:
                tokens = self.__load_matedata('token_en.pkl')
            if tokens is None:
                tokens = self.queries['query'].str.split()
                tqdm.pandas(desc='tokens')
                tokens = tokens.progress_apply(__get_sequence)
                if self.website.trim_space:
                    self.__save_matedata(tokens, 'token_en_trim.pkl')
                else:
                    self.__save_matedata(tokens, 'token_en.pkl')

        return tokens


    def _load_pattern(self, verbose):
        '''
        Get query compressed size pattern.
        '''
        patterns = None
        encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)

        def __get_patterns(string):
            '''
            Get possible size patterns of a query string.
            Considering counter parameter if any exist.
            '''
            size_sequences = [[] for _ in range(8)]

            # Initial bits number from 1 to 8 (+2 octets)
            init_bytes = [b'AA0', b'AAA', b'AAB', b'AAX', b'XX0', b'XXA', b'XXB', b'XXX']
            query_bytes = b''

            ct = self.website.ct_start

            # Keep track of how far through an octet we are
            for char in string:
                if char == '\'' and self.website.encode_apost:
                    query_bytes += b'%27'
                elif char == ' ' and self.website.encode_space:
                    query_bytes += b'%20'
                else:
                    query_bytes += bytes(char, encoding='utf8')

                if char == '\'':
                    if self.website.ct_type == 'cp':
                        ct += 1
                    continue

                if char == ' ' and self.website.trim_space:
                    if self.website.ct_type == 'cp':
                        ct += 1
                    continue

                if self.website.ct_type == 'no':
                    encode_bytes = query_bytes
                else:
                    ct_bytes = bytes(str(ct), encoding='utf8')
                    encode_bytes = query_bytes + ct_bytes

                for i in range(len(init_bytes)):
                    size_sequences[i].append(len(encoder.encode(init_bytes[i] + encode_bytes)))

                ct += 1

            return [np.diff(x).tolist() for x in size_sequences]

        # Compressed pattern is valid only for HTTP/2 requests without changing bytes
        if self.website.http_version == 2 and self.website.change_byte == 0:
            if verbose:
                print('Loading query patterns')
            if self.chinese:
                patterns = self.__load_matedata('pattern_zh_%s.pkl' % self.website)
                if patterns is None:
                    tqdm.pandas(desc='pinyin')
                    string = self.queries['query'].progress_apply(lambda x: '\''.join(py.get_pinyin(x).split('-')))
                    tqdm.pandas(desc='patterns')
                    patterns = string.progress_apply(__get_patterns)
                    self.__save_matedata(patterns, 'pattern_zh_%s.pkl' % self.website)
            else:
                patterns = self.__load_matedata('pattern_en_%s.pkl' % self.website)
                if patterns is None:
                    tqdm.pandas(desc='patterns')
                    patterns = self.queries['query'].progress_apply(__get_patterns)
                    self.__save_matedata(patterns, 'pattern_en_%s.pkl' % self.website)

        elif verbose:
            if self.website.http_version == 1.1:
                print('Compressed pattern is ignored for HTTP/1.1')
            else:
                print('Compressed pattern is invalid for changing byte parameters')

        return patterns


    def _load_rhythm(self, verbose):
        '''
        Get query typing rhythm.
        '''
        def __get_rhythms(string):
            '''
            Get the typing rhythms of a string.
            '''
            rhythms = {'mean': [0], 'std': [0]}

            for i in range(len(string) - 1):
                mean = std = 0

                if string[i].islower() and string[i+1].islower():
                    bigram = (string[i], string[i+1])

                    mean = self.bigrams.loc[bigram, 'mean']
                    std = self.bigrams.loc[bigram, 'std']

                if string[i+1] == ' ' and self.website.trim_space:
                    continue

                rhythms['mean'].append(mean)
                rhythms['std'].append(std)

            return rhythms

        if verbose:
            print('Loading query rhythm')
        if self.chinese:
            rhythms = self.__load_matedata('rhythm_zh.pkl')
            if rhythms is None:
                tqdm.pandas(desc='pinyin')
                string = self.queries['query'].progress_apply(lambda x: py.get_pinyin(x))
                tqdm.pandas(desc='rhythms')
                rhythms = string.progress_apply(__get_rhythms)
                self.__save_matedata(rhythms, 'rhythm_zh.pkl')
        else:
            rhythms = self.__load_matedata('rhythm_en.pkl')
            if rhythms is None:
                tqdm.pandas(desc='rhythms')
                rhythms = self.queries['query'].progress_apply(__get_rhythms)
                self.__save_matedata(rhythms, 'rhythm_en.pkl')

        return rhythms
    
    
    def filter_by_length(self, keystrokes):
        '''
        Filter queries according to input length.
        '''
        self.candidates = []
        self.candidate_idx = []
        for i in range(len(keystrokes)):
            # Get keystroke number
            number = len(keystrokes[i])

            # Filter by length
            candidates = self.queries[self.length == number]
            self.candidates.append(candidates)
            self.candidate_idx.append(candidates.index)

        return self.candidates


    def filter_by_token(self, keystrokes):
        '''
        Filter queries according to delimited word/syllable length.
        '''
        def check_token(token, target):
            '''
            Check if query token accords with the keystroke token.
            '''
            conform = True
            for i in range(len(target)):
                if target[i] == -1:
                    continue
                elif target[i] != token[i]:
                    conform = False
                    break

            return conform

        for i in range(len(keystrokes)):
            # Get candidate delimiter sequence
            tokens = self.tokens.iloc[self.candidate_idx[i]]

            # Get keystroke delimiter sequence
            token = keystrokes[i]['delimiter'].tolist()

            # Filter by token length
            accordant = tokens.apply(check_token, target=token)
            self.candidates[i] = self.candidates[i][accordant == True]
            self.candidate_idx[i] = self.candidates[i].index

        return self.candidates


    def filter_by_pattern(self, keystrokes):
        '''
        Filter queries according to the size pattern of compressed string.
        '''
        def __check_patterns(patterns, target):
            '''
            Check if any pattern accords with the keystroke pattern.
            '''
            # Section number of purified keystrokes
            n = target.count(-1) + 1
            end = -1
            for i in range(n):
                start = end + 1
                if i == n - 1:
                    end = None
                else:
                    end = start + target[start:].index(-1)
                tar_part = target[start:end]

                conform = False
                for pattern in patterns:
                    pat_part = pattern[start:end]
                    if pat_part == tar_part:
                        conform = True
                        break

                if conform == False:
                    return False

            return True
        
        if self.patterns is not None:
            for i in range(len(keystrokes)):
                # Get candidate size pattern
                patterns = self.patterns.iloc[self.candidate_idx[i]]

                # Get keystroke size difference
                pattern = keystrokes[i]['pattern'].tolist()[1:]

                # Filter by query string size pattern
                accordant = patterns.apply(__check_patterns, target=pattern)
                self.candidates[i] = self.candidates[i][accordant == True]
                self.candidate_idx[i] = self.candidates[i].index

        return self.candidates


    def rank_by_rhythm(self, keystrokes):
        '''
        Rank queries according to typing rhythm.
        '''
        chinese = self.chinese or self.website.trim_space

        def __get_score(rhythms, target):
            '''
            Calculate the query probability.
            '''
            def __norm_score(interval, mean, std):
                '''
                Score by the PDF of norm distribution.
                '''
                return -np.log10(stats.norm.pdf(interval, loc=mean, scale=std))

            score = 0
            n = 0
            i = j = 1
            while i < len(target):
                # Fake keystroke timings
                if target[i] == 1000:
                    i += 1
                    j += 1
                    continue

                # Inter-token timings
                if rhythms['mean'][j] == 0:
                    i += 1
                    j += 1
                    if chinese:
                        j += 1
                    continue

                interval = target[i]
                mean = rhythms['mean'][j]
                std = rhythms['std'][j]

                score += __norm_score(interval, mean, std)
                n += 1
                i += 1
                j += 1

            return score / n
            
        for i in range(len(keystrokes)):
            if len(self.candidates[i]) == 0:
                continue

            # Get candidate rhythms
            rhythms = self.rhythms.iloc[self.candidate_idx[i]]

            # Get keystroke timing intervals
            rhythm = keystrokes[i]['interval'].tolist()

            # Rank by keystroke rhythms
            scores = rhythms.apply(__get_score, target=rhythm)
            self.candidates[i]['rank'] = scores.rank(method='first').astype(int)

        return self.candidates
