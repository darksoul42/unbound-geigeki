# unbound-geigeki
Unbound module for attack interception(Geigeki)
Unbound 攻撃の「迎撃」用モジュール

## History / 経緯

This project was started within AsahiNet in fall 2014,
as an attempt to deal with the ongoing DNS cache attacks
by open DNS resolvers using pseudo-random subdomains.

These attacks would consistently consume huge amounts of traffic,
memory, and clog the DNS server recursive queue.

Unbound being just better at handling huge queues of recursive queries,
prompted us to switch over once we had implemented AAAA filtering.

Based on the output of the "unbound-control lookup" command,
we also developped an extension to the python API :
https://www.unbound.net/pipermail/unbound-users/2015-January/003680.html

After a few trial runs, we had succeeded in developing a functional,
real-time interception system :
https://www.unbound.net/pipermail/unbound-users/2015-January/003684.html

この案件が動き出したのは２０１４年の秋頃で、
当時激しかった、オープンリゾルバがPRSDを用いて
DNSキャッシュサーバーに対して行う攻撃を緩和する手段として、
Geigekiシステムは朝日ネットが開発したものである。

これらの攻撃は、大量のトラフィックの発生のみならず、
メモリ逼迫や再帰クエリのキューの逼迫も起こしていた。

そこで、unboundがそもそも再帰クエリのキューの管理に長けていたため、
AAAAフィルターを実装した段階で、乗り換えを決めた。

そこから、「unbound-control lookup」の出力を元に、
python APIの拡張を開発した：
https://www.unbound.net/pipermail/unbound-users/2015-January/003680.html

動作試験の末、リアルタイムで攻撃を迎撃し、中和するシステムの開発に成功していた：
https://www.unbound.net/pipermail/unbound-users/2015-January/003684.html

## Mechanism / 原理

### In-memory tables / メモリ内テーブル

This module operates on non-cached DNS queries, and will maintain in-memory tables for :
- client address
- query target's delegation point, refered afterwards to as "domain"
- pair of client/domain

本モジュールは、キャッシュされていないクエリに対して実行され、下記のメモリ内のテーブルを管理する：
- クライアントのアドレス
- クエリ対象の委任ポイント、以後は「ドメイン」と称す
- クライアントとドメインのペア

### Tracked statistics / 監視している統計

The following statistics are kept track of :
- Count of sent normal queries (everything except ANY)
- Count of returned NXDOMAIN errors
- Count of sent ANY query
- Count of returned RRSETs
- Count of processed CNAME records

上記の対象の下記の統計を監視する：
- 通常クエリの数（ANY以外）
- 返ってきたNXDOMAINエラーの数
- ANYクエリの数
- 返ってきたRRSETの数
- 処理したCNAMEレコードの数

### Thresholds / しきい値

For each statistics counter / memory table, there are specific thresholds.

By looking at full scale DDoS attacks we suffered, and applying a 80% ratio on it, we reached these numbers :
- A given DDoS participant gives out 4 attack queries / second to that domain, which is around 1200 cache-missing queries in 5 minutes.
- A given domain in a DDoS therefore takes around a hundred of these at the very least.
- One can therefore start flagging a client-domain relation around 5 cache-missing queries in 5 minutes.
(We are never outright blocking ! the purpose is to contain an attack without harming legitimate use)

上記の統計・テーブルに対して、任意のしきい値を適用していく。

我々が体験したDDoS攻撃を元に、しきい値を８０％に設定して、下記の数値に至った：
- DDoSへの加害者１台は、1件のドメイン当たりに、秒速４件のクエリを繰り出す。つまり、５分間、キャッシュにヒットしないクエリが１２００件になる。
- 攻撃の的になっている１件のドメインは少なくとも、その１００倍を受けてしまっている。
- つまり、あるクライアントがあるドメインと少なくない関連を持っているだろう、と疑い始められるのは、５分間にキャッシュミスしたクエリが５件以上になった段階となる。
（これはあくまで「疑う」だけであって、最初から「ブロック」することが趣旨ではない。趣旨はあくまで、正当利用を通しつつ、攻撃を中和することにある）

### Decision process (summarized) / 判断フロー（概要）

There are two cases for blocking queries :
- A client breaches the "single client" threshold (this guy is sending way too much stuff to be legit, no matter what), or the "client-domain"　maximum threshold
- A domain is above the DDoS threshold (given how many queries it has received in five minutes, it's being hammered), and the "client-domain"　is within suspicion range

For mitigation of false positives :
- We first make an initial decision like described above by using the normal, ANY and NXDOMAIN counters and positive thresholds
- This decision is counterbalanced by checking if the RRSET counter is superior to zero, and if so, this means this domain, or client, or client-domain pair actually have dealt with meaningful info and are probably not implied in a bonafide DDoS, since they provide stuff that will fill the cache with meaningful info.

ブロックされるパターンは２つ：
- クライアントは、単体で加害者として認定される（つまり、正当であるはずがないぐらいの大量のクエリを送信している）、又は「クライアント・ドメイン」の最大しきい値を超えている
- ドメインは、DDoSを受けていると判断するしきい値を超えている（過去５分間で、明らかに過剰利用されている）、そして「クライアント・ドメイン」の疑惑しきい値を超えている

false positiveを軽減するための救済装置：
- 一次判断は、上記の通り、「通常クエリ」、「ANYクエリ」、「NXDOMAIN」カウンターに基づいて行っている
- そこから救済装置として、RRSETカウンターがゼロ以上の場合、このドメイン又はクライアント、又はクライアント・ドメインのペアが実際意味のある情報を持ったこと

### Caveats / 特記事項

Queries are handled with the following caveats :
- Geigeki only processes queries that are not already present within the cache. A cached query will bypass the python module.
- Some domains with very peculiar uses are registered in a whitelist (100 times normal threshold)
- PTR queries to in-addr.arpa are automatically whitelisted
- Should unbound be running with the AAAA filter patch, AAAA queries will be ignored
- When dealing with IPv6 clients, it will by default aggregate clients to the common /64 prefix.
It is also possible to specify exceptions for an ISP's own subnets (such as /48 or /56 for specific ranges)

You also need to be wary of the fact that thresholds are to be thoroughly tested for each environment and fine-tuned.
This module does not have an automatic learning feature.

クエリの処理の際は、下記の特別処理を施す：
- Geigekiは、キャッシュにないクエリしか処理しない。つまり、キャッシュにあるクエリはpythonモジュールを経由しない
- 通常と異なる利用のドメインは、ホワイトリストに登録する（通常のしきい値の100倍）
- in-addr.arpa宛のPTRクエリは自動的にホワイトリスト扱いになる
- unboundにAAAAフィルターのパッチが当っている場合、AAAAクエリーが無視される
- IPv6クライアントを処理する際、通常は/64単位でまとめられる。
ISPの場合、自社サブネットのための処理例外を定義出来る（例えば、特定のレンジを/48又は/56でまとめる等出来る）

## How to use / 利用方法

### How to install / 設定の方法

1. Ensure you have the "python-ipaddress" package installed, and a version of unbound built with the python interpreter.
python対応のunboundや、「python-ipaddress」パッケージがインストールされていることを確認してください。
2. Install the "geigeki.py" file somewhere (For instance, `/etc/unbound/geigeki.py`)  
どこかに「geigeki.py」を配置する（例：`/etc/unbound/geigeki.py`）
3. Modify your unbound configuration in the following fashion :  
unbound設定を下記の様に変更する：
```
server:
    [...]
    module-config: "python iterator"

python:
    python-script: "/etc/unbound/geigeki.py"
```
4. `module-config` must include `python` before `iterator`.  
`module-config`は、どうしても`iterator`の前に`python`を指定しなければならない。
5. Add a `python:` section and a `python-script` parameter as described above. Warning: This means Geigeki will not work if you already need another python script.  
 設定に`python:`セクションを足して、`python-script`のパラメーターを上記の通りに追加する。注意：Geigekiは、他のpythonスクリプトと同時に設定出来ない。
6. Restart unbound.  
unboundを再起動する

### How to do a test run / 試験運用の方法

If in `geigeki.py` you declare `DEBUG = True`, query calculations will be made, but the ultimate result will be ignored.
It makes it possible to see what would have happened with a given threshold or whitelist, without interfering with user queries.
The default is `DEBUG = False`.

`geigeki.py`の中に`DEBUG = True`と定義したら、クエリに対する計算は行われるが、最終的な結果は無視される。
これにより、ある閾値又はホワイトリストの効果を確認できつつ、実際にユーザーのクエリに干渉しない。
既定値は`DEBUG = False`。

### How to declare whitelisted domains / ホワイトリストへの追加方法

In `geigeki.py`, a set of whitelisted domains is declared in the following way by default.
`geigeki.py`で、ホワイトリストされたドメインは下記の様に定義されている：
```
WHITELIST_DOMAINS = set([
                        # Your own domains here (such as domains that might end up in search domains on customer premises)
#                        "my.company.tld", "other.domain.tld",
                        # Known security related services
                        "avts.mcafee.com.", "avqs.mcafee.com.", "geoipd.global.sonicwall.com.", "trendmicro.com.", "sbl.spamhaus.org.", "bl.spamcop.net.", "zen.spamhaus.org.",
                        ])
```

It is important for performance when matching domains, to keep the array of domains as a set with the above syntax.
Also, these domains must be "delegation points" with actual NS records.
You can look at the logs provided by Geigeki among the unbound logs to confirm the delegation point for a specific query.

上記のシンタックス通り、set()でドメインの配列を変換することは、ドメインのマッチ処理で性能を保証するために重要なことである。
そして、そこに入るドメインは、実際NSレコードを持った「委任ポイント」でなければならない。
unboundの通常のログに含まれるGeigekiの追加ログから、特定のクエリの委任ポイントを確認出来る。

### How to declare IPv6 prefixes for aggregation / 集約するIPv6プレフィックスの定義の仕方

In `geigeki.py`, a dictionary of high-level IPv6 prefixes and the length of prefixes given out to users is declared in the following way.  
`geigeki.py`で、高位のIPv6プレフィックスと、ユーザーに割り振られたプレフィックス長さの関連付けは下記の様に定義されている：
```
IPV6_PREFIXES_MAP = dict([
                            ("2001::/16", 64),
                         ])
```

This means that any IPv6 address belonging to 2001::/16 will be aggregated as /64 prefixes, cutting any bits below.
This allows all the devices possessed by a user to be viewed as belonging to one specific connection.
The first match will be used, so it is best to define the smallest prefixes first.
By default, all IPv6 addresses are aggregated under /64 prefixes.

上記の定義は、2001::/16の配下のすべてのIPv6アドレスが、/64のプレフィックスで集約され、それより下のビットが切られる、という意味である。
これにより、特定のユーザーが所有するすべてのデバイスがその回線に集約される。
最初にマッチした結果が採用されるので、一番細かいプレフィックスを先に定義するべき。
既定の挙動では、すべてのIPv6アドレスは/64のプレフィックス毎に集約される。

## Logs / ログ

Geigeki will produce extra logs to make explicit what it is doing.  
Geigekiは、挙動を明らかにするために、追加のログを出力する。

### Logs on intialization of Geigeki / Geigeki初期化の際に出るログ

Here is what Unbound and Geigeki will output when starting up.  
UnboundとGeigekiが起動時に表示するログ：
```
notice: init module 0: python
info: ASN-DDoS-geigeki: init called, module id is 0, port: 53, script: '/etc/unbound/geigeki.py'
info: ASN-DDoS-geigeki: Presence of AAAA filter patch : True
info: ASN-DDoS-geigeki: Standard thresholds :
info: ASN-DDoS-geigeki: - CLIENTDOMAIN_THRESHOLDS : [500, 450, 10, 5000, 500]
info: ASN-DDoS-geigeki: - CLIENT_THRESHOLDS : [10000, 9000, 200, 10000, 10000]
info: ASN-DDoS-geigeki: - DDOS_CLIENTDOMAIN_THRESHOLDS : [5, 3, 2, 500, 50]
info: ASN-DDoS-geigeki: - DDOS_DOMAIN_THRESHOLDS : [1000, 600, 400, 10000, 10000]
info: ASN-DDoS-geigeki: Standard decrements :
info: ASN-DDoS-geigeki: - CLIENTDOMAIN_DECREMENTS : [100.0, 90.0, 2.0, 100.0, 100.0]
info: ASN-DDoS-geigeki: - CLIENT_DECREMENTS : [2000.0, 1800.0, 40.0, 2000.0, 2000.0]
info: ASN-DDoS-geigeki: - DDOS_CLIENTDOMAIN_DECREMENTS : [1.0, 0.6, 0.4, 10.0, 10.0]
info: ASN-DDoS-geigeki: - DDOS_DOMAIN_DECREMENTS : [200.0, 120.0, 80.0, 2000.0, 2000.0]
info: ASN-DDoS-geigeki: Whitelisted domains : 10
info: ASN-DDoS-geigeki: Whitelist thresholds :
info: ASN-DDoS-geigeki: - WHITELIST_CLIENTDOMAIN_THRESHOLDS : [50000, 45000, 1000, 50000, 50000]
info: ASN-DDoS-geigeki: - WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS : [500, 300, 200, 5000, 5000]
info: ASN-DDoS-geigeki: - WHITELIST_DDOS_DOMAIN_THRESHOLDS : [100000, 60000, 40000, 1000000, 1000000]
info: ASN-DDoS-geigeki: Whitelist decrements :
info: ASN-DDoS-geigeki: - WHITELIST_CLIENTDOMAIN_DECREMENTS : [10000.0, 9000.0, 200.0, 10000.0, 10000.0]
info: ASN-DDoS-geigeki: - WHITELIST_DDOS_DOMAIN_DECREMENTS : [20000.0, 12000.0, 8000.0, 200000.0, 200000.0]
info: ASN-DDoS-geigeki: Rejection holding threshold/decrement :
info: ASN-DDoS-geigeki: - DOMAIN_BURST_THRESHOLD : 150
info: ASN-DDoS-geigeki: - DOMAIN_BURST_DECREMENT : 30.0
notice: init module 1: iterator
info: start of service (unbound 1.4.22).
```

Thresholds match the counters mentioned in "Tracked statistics".  
Most of these can be configured by editing `geigeki.py`.  
上記のTHRESHOLD(閾値)は、「監視している統計」で説明している内容である。  
`geigeki.py`を編集して、それらの設定項目を操作出来る。

All of Geigeki related logs are prefixed with the keyword `ASN-DDoS-geigeki` so that it is easier to sort out.  
整理しやすくするために、すべてのログに`ASN-DDoS-geigeki`というキーワードをつけている。

### Logs produced for every query processed by Geigeki / Geigekiがクエリ処理する際に出るログ

All query logs will be tagged with `(DEBUG)` if DEBUG is set to True.  
DEBUGがTrueな場合、クエリ関連のログはすべて`(DEBUG)`でタグ付けられる。

#### Allowed queries / 許可されたクエリ

```
info: <CLIENT> <HOST.DOMAIN.TLD> A IN
info: ASN-DDoS-geigeki: allowed <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```

This should be the most common message someone sees.  
これは一番一般的なメッセージである。

In DEBUG mode, it will be displayed like this.  
DEBUGモードでは、下記の表示になる：
```
info: <CLIENT> <HOST.DOMAIN.TLD> A IN
info: ASN-DDoS-geigeki: allowed (DEBUG) <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```

#### Rejected queries / 拒否されたクエリ

```
info: <CLIENT> <HOST.DOMAIN.TLD> A IN
info: ASN-DDoS-geigeki: rejected <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```

This is what is displayed when Geigeki decided to reject a query.  
Geigekiが拒否判定を出した際、上記の表示になる。

In DEBUG mode, it will be displayed like this.  
DEBUGモードでは、下記の表示になる：
```
info: <CLIENT> <HOST.DOMAIN.TLD> A IN
info: ASN-DDoS-geigeki: rejected (DEBUG) <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```

For a potential rejection, every time a query count index reaches a multiple of 25, the following messages will also be displayed :
```
info: ASN-DDoS-geigeki: LOOKUP stats on domain <DOMAIN.TLD> by <CLIENT> (domain): client([5002, 631, 0, 0, 0] / [10000, 9000, 200, 10000, 10000]) domain([5000, 629, 0, 0, 0] / [1000, 600, 400, 10000, 10000]) clientdomain([5000, 629, 0, 0, 0] / [500, 450, 10, 5000, 500] / [5, 3, 2, 500, 50])
info: ASN-DDoS-geigeki: LOOKUP result on domain <DOMAIN.TLD> by <CLIENT>: single_attack_on_domain_by_client=True single_attack_by_client=False is_domain_ddosed=True is_client_member_of_ddos=True
```

These logs contain the keyword `LOOKUP` to make it easy to locate statistics for a rejection in the logs.  
The expressions for `LOOKUP stats` and `LOOKUP result` are also static to help distinction and further filtering by domain or client.  
拒否判定の際の統計をログからより簡単に抽出出来るために、`LOOKUP`という単語を含んでいる。  
更に、`LOOKUP stats`や`LOOKUP result`の表示は固定されていて、ドメインやクライアント毎にフィルターしやすくなっている。

The `LOOKUP stats` explain what the client has been doing recently. In this example :
- The client has sent 5002 normal queries, 631 of which ended in NXDOMAIN, no ANY queries, and did not receive a single RRSET or a single CNAME.
-- None of the client standalone thresholds are breached
- The domain has received 5000 normal queries, 629 of which ended in NXDOMAIN, no ANY queries, and no RRSET or CNAMEs have been received for it.
-- The 629 NXDOMAIN errors are above the threhold of 600, which flags the domain as being exposed to a DDoS
- The client has sent 5000 normal queries to this domain, 629 of which ended in NXDOMAIN, no ANY queries, and did not receive a single RRSET or a single CNAME.
-- The 629 NXDOMAIN errors are above the threshold of 3, which flags the client as maybe participating in a DDoS on this domain -> Reject
-- The 629 NXDOMAIN errors are above the threshold of 450, which flags the client as explicitely attacking the domain -> Reject

The `LOOKUP result` indicates the four decision factors we use :
- Whether the client is attacking a domain on his own -> if True then this client querying this domain will be rejected
- Whether the client is attacking the cache server on his own -> if True then all of this client's queries will be rejected
- Whether the targeted domain is seen as under attack -> Has no impact on its own, requires the client to be suspected to result in a rejection
- Whether the client is suspected of attacking the targeted domain -> See above.

`LOOKUP stats`で、クライアントの最近の挙動が説明される。今回の事例：
- 当該クライアントは5002件の通常クエリを投げて、そのうち631がNXDOMAINで終わった。ANYクエリを送らなかったが、RRSETやCNAMEを1個ももらわなかった。
-- いずれの閾値も超えられてない
- 当該ドメインは5000件の通常クエリを受け、そのうち629件がNXDOMAINで終わった。ANYクエリを受けなかったが、RRSETやCNAMEは1個も観測されなかった。
-- NXDOMAINエラー629件で、600の閾値を超え、ドメインが「DDoSを受けている」判定になる
- 当該クライアントは、当該ドメインに対し、5000件の通常クエリを投げて、そのうち629件がNXDOMAINで終わった。ANYクエリを送らなかったが、RRSETやCNAMEを1個ももらわなかった。
-- NXDOMAINエラー629件で、3の閾値を超え、クライアントに「DDoSに加担している疑惑」フラグが立つ → その時点で拒否判定される
-- NXDOMAINエラー629件で、450の閾値を超え、クライアントが「単独攻撃を仕掛けている」フラグが立つ → その時点で拒否判定される

`LOOKUP result`は、判断材料を説明する：
- 当該クライアントは単独攻撃をしているのか → Trueの場合、当該クライアントの当該ドメインへのクエリが拒否される
- 当該クライアントが当キャッシュサーバーを単独攻撃しているのか → Trueの場合、当該クライアントの一切のクエリが拒否される
- 当該ドメインが攻撃されているとみなされているか → このフラグ単体で効果はなく、拒否判定はクライアントにも何らかの疑惑フラグが立たなければならない
- 当該クライアントが当該ドメインを攻撃している疑惑があるか → 上記参照

#### Ignored queries / 無視されたクエリ

```
info: ASN-DDoS-geigeki: ignored <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```

In DEBUG mode, it will be displayed like this.
DEBUGモードでは、下記の表示になる：
```
info: <CLIENT> <HOST.DOMAIN.TLD> A IN
info: ASN-DDoS-geigeki: ignored (DEBUG) <CLIENT> <HOST.DOMAIN.TLD> (<DOMAIN.TLD>) A IN
```
