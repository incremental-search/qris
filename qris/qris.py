
try:
    from packets import Packets
    from queries import Queries
except:
    from .packets import Packets
    from .queries import Queries


def QRIS(pcap, website, chinese, queryset, bigrams, trident, topk, verbose):
    '''
    Query Recognition in Incremental Search.
    '''
    # Load network packets
    packets = Packets(pcap, website)
    if website is None:
        print('Detected website:', packets.website)
    if verbose:
        print('Server IP:', packets.packets.loc[0, 'dst'])

    # Correlate keystroke packets with DFA states
    keystrokes = packets.correlate_state(chinese, trident)
    if verbose:
        print('Keystrokes:\n', keystrokes)
    
    # Load query set and metadata
    queries = Queries(packets.website, chinese, queryset, bigrams, verbose)
    if verbose:
        print('Number of queries:', len(queries.queries))

    # Filter by query length (keystroke number)
    candidates = queries.filter_by_length(keystrokes)
    if verbose:
        print('Filtered by length:', [len(x) for x in candidates])

    # Filter by query token length (delimiter sequence)
    keystrokes = packets.delimit_token(chinese)
    candidates = queries.filter_by_token(keystrokes)
    if verbose:
        print('Filtered by token:', [len(x) for x in candidates])

    # Filter by query compressed size pattern
    keystrokes = packets.size_pattern()
    candidates = queries.filter_by_pattern(keystrokes)
    if verbose:
        print('Filtered by pattern:', [len(x) for x in candidates])

    # Rank by query typing rhythm (keystroke timing)
    keystrokes = packets.timing_interval()
    candidates = queries.rank_by_rhythm(keystrokes)
    if verbose:
        print('Ranked by rhythm:\n', [x.sort_values('rank') if len(x) > 0 else x for x in candidates])

    # Return inferred queries
    querylist = []
    for group in candidates:
        if len(group) == 0:
            continue
        ranked = group.sort_values('rank')['query']
        if len(ranked) < topk:
            querylist += ranked.tolist()
        else:
            querylist += ranked[:topk].tolist()

    return querylist
