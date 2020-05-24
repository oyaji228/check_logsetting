＃check_logsetting

# 初めに

- 二つのpaloalot筐体の設定のうち、Log-settingの相関関係を調べるプログラムです。
- 最低二つのconfigが必要。最低一つは西拠点のconfigが必要。
- 以降使い方をまとめるので使ってみてね。
- 以降出てくるNCはセキュリティなどを飛ばす先となるあのサーバのこと。

# 作成者
- 2020.5.23
- sunao.yamaguchi(oyaji)


# 環境
* python 3.7.4
* module:sys,re


# 使い方
1. log-settingチェックしたいconfigを指定する

- ”file.txt”にconfigが保存されているファイルのパスを記入。
- (注意) ＜faile path＞ 以外の記載は変更しないこと。書き換えるとプログラムが動かなくなる。
- (注意2）utm_conf_path:の後ろは必ずスペースを開けること。開けないとプログラムが動かなくなる。
- (注意3) ファイル名は必ずホスト名をつけること。そうしないと結果がわかりづらくなる。

```
	:
	:
utm_conf_path: <file path>
utm_conf_path: <file path>
utm_conf_path: <file path>
utm_conf_path: <file path>
	:
	:
	:
```



2. python環境で実行

```
sunao@hoge:code# ll
total 40
-rw-r--r--  1 sunao  staff  13272  5 24 17:25 check_logsetting.py
-rw-r--r--  1 sunao  staff    802  5 24 17:09 files.txt
sunao@hoge:code#
sunao@hoge:code#
sunao@hoge:code#python check_logsetting.py files.txt
sunao@hoge:code#


~~出力結果~~
sunao@hoge:code#python check_logsetting.py files.txt


 ************************************************
 *** ＜西側の装置ホスト名＞ : BCP Seetting (WEST)  ***	
 ************************************************

 *** Relationship between Log-setting and NCserver ***
====================================================================================
| Log-Setting number	|  Target NC server name	|  Target NC server address
====================================================================================
| Log-Setting-1			|  Syslog-Server-NC-1		|  10.1.1.1	
| Log-Setting-2			|  Syslog-Server-NC-2		|  10.1.1.2	
		:							:					  :
| Log-Setting-15		|  Syslog-Server-NC-7		|  10.1.1.Y
| Log-Setting-16		|  Syslog-Server-NC-8		|  10.1.1.Z	
====================================================================================


 *** Relationship between security-rules(per vsys) and Log-setting ***
====================================================================================
|  VSYS Number		|  Security Rules				|  Log-setting Number	
====================================================================================
|   vsys2			|  Security-Rules-2-1			|  Log-Setting-1	
|   vsys2			|  Security-Rules-2-2			|  Log-Setting-1	
	  :							:							:
|   vsysZ			|  Security-Rules-Z-1			|  Log-Setting-1	
|   vsysZ			|  Security-Rules-Z-2			|  Log-Setting-1	
|====================================================================================

 *** Relationship between VSYS and [N|V] number ***
====================================================================================
|  VSYS Number		|  V number			|  N Number			|  Status	
====================================================================================
|   vsys2			|  XXXXXXXXX		|  YYYYYYYYY		|  full
|   vsys3			|  XXXXXXXXX		|  YYYYYYYYY		|  full
	  :						:					:				:
|   vsysY			|  XXXXXXXXX		|  YYYYYYYYY		|  empty
|   vsysZ			|  XXXXXXXXX		|  YYYYYYYYY		|  empty
====================================================================================


 ******************************************************
 *** ＜東側の装置ホスト名＞ : BCP Src Seetting (EAST)  ***	
 ******************************************************

 *** Relationship between Log-setting and NCserver ***
====================================================================================
| Log-Setting number	|  Target NC server name	|  Target NC server address
====================================================================================
| Log-Setting-1			|  Syslog-Server-NC-1		|  10.1.1.1	
| Log-Setting-2			|  Syslog-Server-NC-2		|  10.1.1.2	
		:							:					  :
| Log-Setting-15		|  Syslog-Server-NC-7		|  10.1.1.Y
| Log-Setting-16		|  Syslog-Server-NC-8		|  10.1.1.Z	
====================================================================================


 *** Relationship between security-rules(per vsys) and Log-setting ***
====================================================================================
|  VSYS Number		|  Security Rules				|  Log-setting Number	
====================================================================================
|   vsys2			|  Security-Rules-2-1			|  Log-Setting-1	
|   vsys2			|  Security-Rules-2-2			|  Log-Setting-1	
	  :							:							:
|   vsysZ			|  Security-Rules-Z-1			|  Log-Setting-1	
|   vsysZ			|  Security-Rules-Z-2			|  Log-Setting-1	
|====================================================================================

 *** Relationship between VSYS and [N|V] number ***
====================================================================================
|  VSYS Number		|  V number			|  N Number			|  Status	
====================================================================================
|   vsys2			|  XXXXXXXXX		|  YYYYYYYYY		|  full
|   vsys3			|  XXXXXXXXX		|  YYYYYYYYY		|  full
	  :						:					:				:
|   vsysY			|  XXXXXXXXX		|  YYYYYYYYY		|  empty
|   vsysZ			|  XXXXXXXXX		|  YYYYYYYYY		|  empty
====================================================================================

										:
										:
								東ホストの数だけある
										:
										:


 ******************************************************
 *** Relationship BCP setting between WEST and EAST ***
 ******************************************************

====================================================================================================================================================================================================================================================
|  BCP Setting (WEST)	 										|	|  BCP Soruce Setting (EAST) 		
====================================================================================================================================================================================================================================================
|   VSYS Number	| V Number	|  Security Rules		| Log-setting	| NC serer IP	|  ==>	|  Hostname							|  VSYS Number	| Security Rules		| Log-setting	| NC serer IP	| diff check	|
====================================================================================================================================================================================================================================================
|   vsys2		| XXXXXXXXX	|  Security-Rules-2-1	| Log-Setting-A	| 10.1.1.1		|  ==>	| <BCPの元となる東側の装置ホスト名>		|   vsysA		|  Security-Rules-A-1	| Log-Setting-A	| 10.1.1.1		|
|   vsys2		| XXXXXXXXX	|  Security-Rules-2-2	| Log-Setting-B	| 10.1.1.2		|  ==>	| <BCPの元となる東側の装置ホスト名>		|   vsysB		|  Security-Rules-B-1	| Log-Setting-B	| 10.1.1.2		|

|   vsysZ		| XXXXXXXXX	|  Security-Rules-Z-1	| Log-Setting-Y	| 10.1.1.Y		|  ==>	| <BCPの元となる東側の装置ホスト名>		|   vsysα		|  Security-Rules-α-1	| Log-Setting-Y	| 10.1.1.Y		|
|   vsysZ		| XXXXXXXXX	|  Security-Rules-Z-1	| Log-Setting-Z	| 10.1.1.Z		|  ==>	| <BCPの元となる東側の装置ホスト名>		|   vsysβ		|  Security-Rules-β-1	| Log-Setting-Z	| 10.1.1.Z		|
====================================================================================================================================================================================================================================================



```

- diff log はまだない。近いうちにやる気があれば実装する。

-　以上。
