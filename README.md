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

この案件が朝日ネットの中で動き出したのは２０１４年の秋頃で、
当時は、オープンリゾルバーがPRSDを使った、
激しいDNSキャッシュサーバーに対する攻撃を中和する手段として開発されたものである。

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

### Tracked statistics / 監視している統計

The following statistics are kept track of :
- Count of sent normal queries (everything except ANY)
- Count of sent ANY query
- Count of returned NXDOMAIN errors
- Count of returned RRSETs

上記の対象の下記の統計を監視する：
- 通常クエリの数（ANY以外）
- ANYクエリの数
- 返ってきたNXDOMAINエラーの数
- 返ってきたRRSETの数

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
- Some domains with very peculiar uses are registered in a whitelist (100 times normal threshold)
- PTR queries to in-addr.arpa are automatically whitelisted
- Should unbound be running with the AAAA filter patch, AAAA queries will be ignored
- When dealing with IPv6 clients, it will by default aggregate clients to the common /64 prefix.
It is also possible to specify exceptions for an ISP's own subnets (such as /48 or /56 for specific ranges)

You also need to be wary of the fact that thresholds are to be thoroughly tested for each environment and fine-tuned.
This module does not have an automatic learning feature.

クエリの処理の際は、下記の特別処理を施す：
- 通常と異なる利用のドメインは、ホワイトリストに登録する（通常のしきい値の100倍）
- in-addr.arpa宛のPTRクエリは自動的にホワイトリスト扱いになる
- unboundにAAAAフィルターのパッチが当っている場合、AAAAクエリーが無視される
- IPv6クライアントを処理する際、通常は/64単位でまとめられる。
ISPの場合、自社サブネットのための処理例外を定義出来る（例えば、特定のレンジを/48又は/56でまとめる等出来る）

## How to use / 利用方法

1. Install the "geigeki.py" file somewhere (For instance, `/etc/unbound/geigeki.py`)
どこかに「geigeki.py」を配置する（例：`/etc/unbound/geigeki.py`）
2. Modify your unbound configuration in the following fashion :
unbound設定を下記の様に変更する：
```
server:
    [...]
    module-config: "python iterator"

python:
    python-script: "/etc/unbound/geigeki.py"
```
    1. `module-config` must include `python` before `iterator`.
       `module-config`は、どうしても`iterator`の前に`python`を指定しなければならない。
    2. Add a `python:` section and a `python-script` parameter as described above. Warning: This means Geigeki will not work if you already need another python script.
       設定に`python:`セクションを足して、`python-script`のパラメーターを上記の通りに追加する。注意：Geigekiは、他のpythonスクリプトと同時に設定出来ない。
3. Restart unbound.
unboundを再起動する
