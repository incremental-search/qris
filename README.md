# Query Recognition in Incremental Search

The Query Recognition in Incremental Search (**QRIS**) is a passive attack system that leverages the size and timing information of incremental search packets to infer the user's query.

QRIS exploits the information leakage contributed by four factors at different data layers:
1. Exact data sizes exposed by TLS ciphers.
2. Static compression lengths of HTTP/2 headers.
3. Accurate keystroke timings exposed by AJAX models.
4. Chinese query details revealed by Pinyin IME.
	
QRIS consists of three stages applied in a pipeline architecture:
1. **State correlation** aims to relate keystroke packets emitted by the incremental search website to specific DFA states.
2. **Ambiguity reduction** utilizes query size distinguishability to reduce the scale of the query set.
3. **Query inference** leverages user's typing rhythm to infer queries from the filtered query set.

Currently support English and Chinese queries. Supported websites include Google, Tmall, Facebook, Baidu, Yahoo, Wikipedia, Csdn, Twitch, Bing.

By default, the [AOL search dataset](https://jeffhuang.com/search_query_logs.html) is used as English query set, and the [THU Open Chinese Lexicon](http://thuocl.thunlp.org/) (THUOCL) is used as Chinese query set. The default keystroke timing model is trained on the [136M keystroke dataset](https://userinterfaces.aalto.fi/136Mkeystrokes/).

#### Reference Format
```
@article{LiLLZ21,
  author    = {Ding Li and
               Wei Lin and
               Bin Lu and
               Yuefei Zhu},
  title     = {Exploiting side-channel leaks in web traffic of incremental search},
  journal   = {Comput. Secur.},
  volume    = {111},
  pages     = {102481},
  year      = {2021},
  doi       = {10.1016/j.cose.2021.102481}
}
```

## Installation

1. Use pip with Python 3.x to install the QRIS package:

```
> pip install https://github.com/incremental-search/qris/archive/main.zip
```

2. (Optional) Download the preloaded metadata for the AOL and THUOCL query sets. Unzip it into the QRIS python installation directory.

	* [metadata](https://mega.nz/file/9cxgGLiZ#-IMdSSrYKPPqt7QQD4qUbtZwoMMPxQ9OH3DVOuJZtC0) (312.05 MB, SHA1: F72D2C22E38BCC0BFBBDA94DDD0697E2B9745E05)


## Usage

The QRIS python package provides a command `qris` to infer the entered search query from a `pcap` file that contains network traffic of incremental search.

Use the command `qris` to get the help message:

```
usage: qris [-h] [--website NAME] [--chinese] [--queryset PATH]
            [--bigrams PATH] [--trident] [--topk K] [--verbose]
            pcap

Query Recognition in Incremental Search

positional arguments:
  pcap             filename of the pcap.

optional arguments:
  -h, --help       show this help message and exit
  --website NAME   name of the website. If not specified, try to identify.
  --chinese        Chinese query entered using Pinyin IME.
  --queryset PATH  filename of the query set (csv format).
  --bigrams PATH   filename of the bigram timing model (csv format).
  --trident        broswer engine is Trident, including broswer IE and old
                   version of Edge.
  --topk K         list the top K inferred queries.
  --verbose        show inference details.
```

Use the following command to run QRIS with default optional arguments:

```
> qris [xx].pcap
```


## Examples

Some traffic samples can be found in `samples` directory. More samples are available from the [ISTD](#related-repositories) traffic dataset.

```
> qris "apple bee restaurant.pcap" --website bing
laser eye correction
bound and determined
south par accounting
camel toe definition
death and depression
laser for cigarettes
apple bee restaurant
cures for depression
funds for relocation
inner bay restaurant

> qris 左氧氟沙星片.pcap --chinese
Detected website: tmall
北京地坛公园
北京日坛公园
宝岗大道总站
罗望子多糖胶
住房部分产权
左氧氟沙星片
非全日制用工
辛芳鼻炎胶囊
北方凹指招潮
翻动扶摇羊角
```


## Related repositories

* [QAIS](https://github.com/incremental-search/qais): the data collection tool that captures network traffic while an English or Chinese query is typed into an incremental search website.

* [ISTD](https://github.com/incremental-search/istd): the traffic dataset that contains 32.4k samples of English and Chinese queries captured on 9 incremental search websites.
