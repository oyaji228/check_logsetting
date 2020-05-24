import sys
import re


def grep_match_pattarn(filepath, split_num_list, pattern, split_letter):
	file = open(filepath)
	lines = file.readlines()
	match_list = []
	split_letter = str(split_letter)
	for line in lines:
		#print(debug)	#debug
		#debug += 1		#debug

		if re.match(pattern, line):		#patternにマッチした行を抜き出し
			result = re.match(pattern, line)
			#print(result)
			result = result.group(0)	
			#print(result)	#debug
			result = re.split(split_letter, result)		#split_letterで指定された文字列で分割
			#print(result)	#debug
			for i in split_num_list:	#指定された欲しい部分だけ抜き出してリストの最後尾に追加(append)
				#print(i)	#debug
				result_split = result[i] 
				match_list.append(result_split)
				pass
		pass
	#print(match_list)		#debug
	return(match_list)
	pass
	


def comment_out(repeat_num):
	i = 0

	for i in range(0,repeat_num):
		#print(i)
		if i == (repeat_num - 1):
			print("")			
			pass
		else:
			print("====", end = '')
			pass	
		pass
	


################################################################################################################################

### main ###


#########################
### ファイルパス読み込み ###
#########################

# 西BCP設定とBCP設定の元となる東configパスを読み込み
filepath = sys.argv[1]
split_num_list = [1]
pattern = '.*utm_conf_path:.*'
split_letter = " "
bcp_conf = grep_match_pattarn(filepath = filepath, split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
#print(bcp_conf)		#debug

# 変数設定
i = 0
j = 0
k = 0
l = 0

result_a = []
result_b = []


split_num_list = []
pattern = []

west_hostname = []
east_hostname = []
west_host_path = []
east_host_path =[]
hostname = []




for i in range(0, len(bcp_conf)):
# for i in range(0, 0):		#debug


	#print(bcp_conf[i])		#debug


	############################## 
	### configからHostnameを取得 ###
	############################## 

	split_num_list = [4]
	pattern = '.*system.*hostname.*'
	split_letter = ' '
	hostname = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
	#print(hostname)

	if re.match('.*naniwa.*', str(hostname)):
		west_hostname.append(str(hostname))
		west_host_path.append(bcp_conf[i]) 
		print("\n\n ************************************************")
		print(" *** {hostname} : BCP Seetting (WEST)  ***	".format(hostname = hostname[0]))
		print(" ************************************************\n")
		pass
	elif re.match('.*karaga.*', str(hostname)):
		east_hostname.append(hostname)
		east_host_path.append(bcp_conf[i]) 
		print("\n\n ****************************************************")
		print(" *** {hostname} : BCP Src Seetting (EAST) ***	".format(hostname = hostname[0]))
		print(" ****************************************************\n")
		pass



	###########################################
	### log-settingとNCサーバの関係性をリスト化	###  
	########################################### 

	split_num_list = [4,8]
	pattern = '.*Log-Setting.*threat-info.*send.*'
	split_letter = ' '
	result_logset_nc = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)

	split_num_list = [4,8]
	pattern = '.*Syslog-Server-NC.*server.*server.*'
	split_letter = ' '
	result_nc_ip = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)

	j = 0
	l = 0
	result_logset_nc_ip = []

	for l in range(0, len(result_logset_nc), 2): #log-setting と NC server name と NC server addressの紐付けをリスト化する
		result_logset_nc_ip.append(result_logset_nc[l])	#リスト result_c に result_aのlog-setting number(A)を追加
		result_logset_nc_ip.append(result_logset_nc[l+ 1])	#リスト result_c に result_aの(A)に対応するNC server nameを追加

		for j in range(0, len(result_nc_ip),2):		#(A)に対応するNC server addressをリストresult_bから探す
			#print("result_a[i+1] = ",result_a[i+1])	#debug
			#print("result_b[j] = ",result_b[j])		#debug
			if (result_logset_nc[l+1] == result_nc_ip[j]):
				#print("match")							#debug
				result_logset_nc_ip.append(result_nc_ip[j+1])
				#print(result_c)						#debug
				pass
			else:
				pass			
			pass
		pass


	print(" *** Relationship between Log-setting and NCserver ***")
	
	comment_out(22)
	print("| Log-Setting number	|  Target NC server name	|  Target NC server address")		
	comment_out(22)
	
	k = 0

	for k in range(0, len(result_logset_nc_ip), 3):
		#print(len(result_c))		#debug
		#print(result_c[k])			#debug
		print("| {result_logsetting_num}		|  {result_ncserver_name}		|  {result_ncserver_address}	".format(result_logsetting_num=result_logset_nc_ip[k], result_ncserver_name=result_logset_nc_ip[k+1], result_ncserver_address=result_logset_nc_ip[k+2]) ) 
		pass

	comment_out(22)
	print('\n')





	################################################
	### security rulesとlog-settingの関係をリスト化 ###
	################################################

	split_num_list = [2,6,8]
	pattern = '.*vsys.*log-setting.*'
	split_letter = ' '
	result_serule_logset = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)

	print(" *** Relationship between security-rules(per vsys) and Log-setting ***")

	comment_out(22)
	print("|  VSYS Number		|  Security Rules		|  Log-setting Number	")		
	comment_out(22)

	m = 0

	for m in range(0, len(result_serule_logset), 3):
		print("|   {result_vsys_west}		|  {result_secirty_rules_west}	|  {result_logsetting_num_west}	".format(result_vsys_west=result_serule_logset[m], result_secirty_rules_west=result_serule_logset[m+1], result_logsetting_num_west=result_serule_logset[m+2]) )
		
		pass

	comment_out(22)
	print('\n')



	####################################
	### vsys毎のV番,N番一覧リストを作成 ###
	####################################

	print(" *** Relationship between VSYS and [N|V] number ***")
	
	comment_out(22)
	print("|  VSYS Number		|  V number		|  N Number		|  Status	")		
	comment_out(22)

	split_num_list = [2,4,-1]
	pattern = '.*vsys.*display-name.*'
	split_letter = '[ |_]'
	result_vsys_vnnum = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)

	m = 0

	for m in range(0, len(result_vsys_vnnum), 3):
		
		if re.match('.*vsys-[0-9].*', result_vsys_vnnum[m+1]):
			result_status = str("empty")
			#print('vsys')			#debug
			pass
		elif re.match('.*V[0-9].*', result_vsys_vnnum[m+1]):
			result_status = str("full")
			#print('Vnumber')		#debug
			pass
		else:
			pass

		print("|   {result_vsys}		|  {result_v_number}		|  {result_n_number}		|  ".format(result_vsys=result_vsys_vnnum[m], result_v_number=result_vsys_vnnum[m+1], result_n_number=result_vsys_vnnum[m+2]) +result_status)
		pass

	pass

	comment_out(22)
	print('\n')




####################################
### 西のBCP設定と東設定の関係リスト ###
####################################

print("\n\n ******************************************************")
print(" *** Relationship BCP setting between WEST and EAST ***")
print(" ******************************************************\n")


comment_out(62)
print("|  BCP Setting (WEST)	 										|	|  BCP Soruce Setting (EAST) 		")		
comment_out(62)
print("|   VSYS Number	| V Number	|  Security Rules		| Log-setting	| NC serer IP		|  ==>	|  Hostname		|  VSYS Number	| Security Rules		| Log-setting	| NC serer IP		| diff check	|")		
comment_out(62)

i = 0
j = 0


for i in range(0, len(west_host_path)):

	# print('i = {i}'.format(i =i))		#debug

	split_num_list = [2,6,8]
	pattern = '.*vsys.*log-setting.*'
	split_letter = ' '
	result_west_vsys_logset_secrule = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)




	for j in range(0, len(result_west_vsys_logset_secrule), 3):

		
		# 西サイトのNCserverのIPアドレスをリスト化
		split_num_list = [4,8]
		pattern = '.*' + result_west_vsys_logset_secrule[j+2] + '.*threat-info.*send.*'
		# print(pattern)

		split_letter = ' '
		result_west_logset_nc = grep_match_pattarn(filepath = west_host_path[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
		# print(result_west_logset_nc)

		west_nc_server = result_west_logset_nc[1]
		# print(west_nc_server)

		split_num_list = [4,8]
		pattern = '.*' + west_nc_server + ' .*server.*server.*'
		split_letter = ' '
		result_west_nc_server = grep_match_pattarn(filepath = west_host_path[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
				
		west_nc_server_ip = result_west_nc_server[1]
		# print(west_nc_server_ip)
		





		# print(result_west_vsys_logset_secrule[j+1])

		# print(' j = {j}'.format(j =j))		#debug
		vsys_num = result_west_vsys_logset_secrule[j]

		split_num_list = [2,4]
		pattern = '.*' + vsys_num + ' .*display-name.*'
		split_letter = ' |_'
		result_vnum = grep_match_pattarn(filepath = bcp_conf[i], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
		# print(result_vnum)

		for k in range(0, len(east_host_path),1):
			
			# print('  k = {k}'.format(k =k))		#debug

			v_num = result_vnum[1]
			# print(v_num)			

			split_num_list = [2,4]
			pattern = '.*display.*' + v_num + '.*'
			split_letter = ' '
			result_east_vnum = grep_match_pattarn(filepath = east_host_path[k], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
			
			# print(result_east_vnum)
			
			east_setting_last = []

			if result_east_vnum == []:	#西サイトのセキュリティルールが所属するVSYSのV番が東サイトのV番と合致しない場合
				# print("v number not match " + str(result_east_vnum))
				east_setting_last = ['------------','------','---------------------------','------------','---------------']
				east_logset = ''
				pass

			
			else:	#西サイトのセキュリティルールが所属するVSYSのV番が東サイトのV番と合致する場合
				# print("v number match " + str(result_east_vnum))
				
				east_hostname_bcpsrc = re.search('u(bp|sp|p)ao[0-9]+[a-z]+',east_host_path[k])
				east_hostname_bcpsrc = east_hostname_bcpsrc.group(0).split()

				# print(result_east_vnum[0])
				# print(result_west_vsys_logset_secrule[j+1])

				split_num_list = [8]
				pattern = '.*' + result_east_vnum[0] + ' .*'  + result_west_vsys_logset_secrule[j+1] + '.*Log-.*'
				# print(pattern)
				split_letter = ' '
				east_logset = grep_match_pattarn(filepath = east_host_path[k], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
				
				# print(east_logset[0])
				# east_logset = east_logset.group(0).split()

				 

				# 東サイトのNCserverのIPアドレスをリスト化
				split_num_list = [4,8]
				pattern = '.*' + east_logset[0] + '.*threat-info.*send.*'
				split_letter = ' '
				result_east_logset_nc = grep_match_pattarn(filepath = east_host_path[k], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)
				# print(result_logset_nc)

				east_nc_server = result_east_logset_nc[1]
				# print(east_nc_server)

				split_num_list = [4,8]
				pattern = '.*' + east_nc_server + ' .*server.*server.*'
				split_letter = ' '
				result_east_nc_server = grep_match_pattarn(filepath = east_host_path[k], split_num_list = split_num_list, pattern = pattern, split_letter = split_letter)

				east_nc_server_ip = result_east_nc_server[1]
				# print(result_east_nc_server,east_nc_server_ip)
				


				#東セットの設定を一つのリストに集約
				east_setting_last.append(east_hostname_bcpsrc[0])
				east_setting_last.append(result_east_vnum[0])
				east_setting_last.append(result_west_vsys_logset_secrule[j+1])
				east_setting_last.append(east_logset[0])
				east_setting_last.append(east_nc_server_ip)


				# print(east_setting_last)
				break


			pass





		# 全集計結果をリストに表示
		print("|   {result_vsys_west}	| {result_vnum}	|  {result_secirty_rules_west}	| {result_logsetting_num_west}	| {west_nc_ip}	|  ==>	| {east_bcpsrc_hostname}		|   {east_bcpsrc_vsys}	|  {east_securty_rules}	| {east_logsetting_num}	| {east_nc_ip}	|"
			.format(
			result_vsys_west=result_west_vsys_logset_secrule[j], result_vnum = result_vnum[1], result_secirty_rules_west=result_west_vsys_logset_secrule[j+1], west_nc_ip = west_nc_server_ip,
			result_logsetting_num_west = result_west_vsys_logset_secrule[j+2], east_bcpsrc_hostname = east_setting_last[0], east_bcpsrc_vsys = east_setting_last[1],
			east_securty_rules = east_setting_last[2], east_logsetting_num = east_setting_last[3],  east_nc_ip = east_setting_last[4]
			)
			)



		# print("| {result_east_vsys}".format(result_east_vsys = result_east_vsys))
		pass

	pass





comment_out(62)
print('\n')








