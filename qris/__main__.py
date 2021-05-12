import sys
import argparse

from qris import QRIS

def main():
    parser = argparse.ArgumentParser(prog='qris', description='Query Recognition in Incremental Search')
    parser.add_argument('pcap', type=str,
                        help='filename of the pcap.')
    parser.add_argument('--website', type=str, metavar='NAME', default=None,
                        help='name of the website. If not specified, try to identify.')
    parser.add_argument('--chinese', dest='chinese', action='store_true',
                        help='Chinese query entered using Pinyin IME.')
    parser.add_argument('--queryset', type=str, metavar='PATH', default=None,
                        help='filename of the query set (csv format).')
    parser.add_argument('--bigrams', type=str, metavar='PATH', default=None,
                        help='filename of the bigram timing model (csv format).')
    parser.add_argument('--trident', dest='trident', action='store_true',
                        help='browser engine is Trident, including browser IE and old version of Edge.')
    parser.add_argument('--topk', type=int, metavar='K', default=10,
                        help='list the top K inferred queries.')
    parser.add_argument('--verbose', dest='verbose', action='store_true',
                        help='show inference details.')
    
    if len(sys.argv) == 1:
        parser.print_help()
        
    else:
        args = parser.parse_args(sys.argv[1:])
        querylist = QRIS(**vars(args))
        print('\n'.join(querylist))

if __name__ == "__main__":
    main()
